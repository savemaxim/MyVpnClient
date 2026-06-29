from __future__ import annotations

from dataclasses import dataclass
import select
import socket
import ssl
import time
from urllib.parse import urlparse

from .ppp import FortinetPppEngine


@dataclass
class TunnelOpenResult:
    status_code: int
    reason: str
    headers: dict[str, str]


class PrefixedSocket:
    def __init__(self, sock: ssl.SSLSocket, prefix: bytes) -> None:
        self.sock = sock
        self.prefix = bytearray(prefix)

    def fileno(self) -> int:
        return self.sock.fileno()

    def setblocking(self, flag: bool) -> None:
        self.sock.setblocking(flag)

    def recv(self, size: int) -> bytes:
        if self.prefix:
            chunk = bytes(self.prefix[:size])
            del self.prefix[:size]
            return chunk
        return self.sock.recv(size)

    def send(self, data) -> int:
        return self.sock.send(data)

    def sendall(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        self.sock.close()


class FortinetTlsTunnel:
    def __init__(
        self,
        base_url: str,
        svpn_cookie: str,
        *,
        verify_tls: bool = True,
        user_agent: str = "Mozilla/5.0 SV1",
        timeout: float = 30.0,
    ) -> None:
        parsed = urlparse(base_url if "://" in base_url else "https://" + base_url)
        if parsed.scheme != "https":
            raise ValueError("Fortinet TLS tunnel requires an https server URL")
        self.host = parsed.hostname or ""
        self.port = parsed.port or 443
        self.server_name = self.host
        self.svpn_cookie = svpn_cookie
        self.verify_tls = verify_tls
        self.user_agent = user_agent
        self.timeout = timeout
        self.sock: ssl.SSLSocket | None = None
        self.tcp_nodelay_enabled = False

    def open(self) -> TunnelOpenResult:
        context = ssl.create_default_context()
        if not self.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.tcp_nodelay_enabled = False
        set_raw_sockopt = getattr(raw_sock, "setsockopt", None)
        if callable(set_raw_sockopt):
            try:
                set_raw_sockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.tcp_nodelay_enabled = True
            except OSError:
                pass
        self.sock = context.wrap_socket(raw_sock, server_hostname=self.server_name)
        set_tls_sockopt = getattr(self.sock, "setsockopt", None)
        if callable(set_tls_sockopt):
            try:
                set_tls_sockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.tcp_nodelay_enabled = True
            except OSError:
                pass
        host_header = self.host if self.port == 443 else f"{self.host}:{self.port}"
        request = (
            "GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            f"Cookie: SVPNCOOKIE={self.svpn_cookie}\r\n"
            "\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        readable, _, _ = select.select([self.sock], [], [], min(self.timeout, 1.0))
        if readable:
            first_bytes = self._read_initial_prefix(5)
            if first_bytes.startswith(b"HTTP/"):
                return self._read_response_headers(first_bytes)
            self.sock = PrefixedSocket(self.sock, first_bytes)
        return TunnelOpenResult(0, "PPP stream pending", {})

    def _read_initial_prefix(self, size: int) -> bytes:
        if self.sock is None:
            raise RuntimeError("Tunnel is not open")

        data = bytearray()
        deadline = time.monotonic() + min(self.timeout, 1.0)
        gettimeout = getattr(self.sock, "gettimeout", None)
        settimeout = getattr(self.sock, "settimeout", None)
        previous_timeout = gettimeout() if callable(gettimeout) else None
        try:
            while len(data) < size:
                timeout = max(0.0, deadline - time.monotonic())
                readable, _, _ = select.select([self.sock], [], [], timeout)
                if not readable:
                    break
                if callable(settimeout):
                    settimeout(timeout)
                try:
                    chunk = self.sock.recv(size - len(data))
                except TimeoutError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            if callable(settimeout):
                settimeout(previous_timeout)
        return bytes(data)

    def run(
        self,
        *,
        should_stop,
        log,
        tap=None,
        routes=None,
        dns=None,
        metric: int = 1,
        on_ready=None,
        on_phase=None,
        on_stats=None,
        on_packet=None,
        trace_flows: bool = False,
        fast_data_path: bool = True,
        negotiation_timeout: float = 90.0,
        idle_timeout: float = 0.0,
        terminate_grace: float = 2.0,
    ) -> int:
        if self.sock is None:
            raise RuntimeError("Tunnel is not open")

        log("myvpn_tunnel TLS tunnel stream is running; starting PPP engine. TCP_NODELAY=" + str(self.tcp_nodelay_enabled).lower())
        return FortinetPppEngine(
            self.sock,
            tap=tap,
            log=log,
            routes=routes or [],
            dns=dns or [],
            metric=metric,
            on_ready=on_ready,
            on_phase=on_phase,
            on_stats=on_stats,
            on_packet=on_packet,
            trace_flows=trace_flows,
            fast_data_path=fast_data_path,
            negotiation_timeout=negotiation_timeout,
            idle_timeout=idle_timeout,
            terminate_grace=terminate_grace,
        ).run(should_stop=should_stop)

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self.sock.close()
        finally:
            self.sock = None

    def _read_response_headers(self, initial_data: bytes = b"") -> TunnelOpenResult:
        if self.sock is None:
            raise RuntimeError("Tunnel is not open")

        data = bytearray(initial_data)
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(1)
            if not chunk:
                raise ConnectionError("Server closed connection before tunnel response headers")
            data.extend(chunk)
            if len(data) > 65536:
                raise ConnectionError("Tunnel response headers are too large")

        header_text = data.decode("iso-8859-1", errors="replace")
        lines = header_text.split("\r\n")
        status_line = lines[0] if lines else ""
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        reason = parts[2] if len(parts) > 2 else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        return TunnelOpenResult(status_code, reason, headers)

