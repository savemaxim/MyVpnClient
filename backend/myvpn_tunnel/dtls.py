from __future__ import annotations

import struct
import ctypes
from ctypes import wintypes
import os
import select
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


CLTHELLO_PREFIX = b"GFtype\x00clthello\x00SVPNCOOKIE\x00"
SVRHELLO_PREFIX = b"GFtype\x00svrhello\x00handshake\x00"


class DtlsUnavailable(RuntimeError):
    pass


def build_fortinet_dtls_client_hello(svpn_cookie: str) -> bytes:
    body = CLTHELLO_PREFIX + svpn_cookie.encode("utf-8") + b"\x00"
    return struct.pack(">H", len(body) + 2) + body


def parse_fortinet_dtls_server_hello(packet: bytes) -> bool:
    if len(packet) < 2:
        return False
    length = struct.unpack(">H", packet[:2])[0]
    if length != len(packet):
        return False
    body = packet[2:]
    if not body.startswith(SVRHELLO_PREFIX):
        return False
    status = body[len(SVRHELLO_PREFIX):].rstrip(b"\x00")
    return status == b"ok"


class OpenSslApi:
    SSL_ERROR_WANT_READ = 2
    SSL_ERROR_WANT_WRITE = 3
    SSL_VERIFY_NONE = 0
    BIO_NOCLOSE = 0
    DTLS1_2_VERSION = 0xFEFD
    SSL_CTRL_SET_MIN_PROTO_VERSION = 123
    SSL_CTRL_SET_MAX_PROTO_VERSION = 124
    BIO_CTRL_DGRAM_SET_CONNECTED = 32
    SSL_OP_NO_EXTENDED_MASTER_SECRET = 1 << 0
    SSL_OP_LEGACY_SERVER_CONNECT = 1 << 2
    SSL_OP_NO_ENCRYPT_THEN_MAC = 1 << 19
    FORTINET_DTLS12_CIPHERS = (
        b"ECDHE-RSA-AES256-GCM-SHA384:"
        b"ECDHE-RSA-AES128-GCM-SHA256:"
        b"AES128-GCM-SHA256:"
        b"AES256-GCM-SHA384"
    )

    def __init__(self) -> None:
        try:
            self.ssl = ctypes.CDLL(str(find_libssl()))
        except OSError as exc:
            raise DtlsUnavailable(f"OpenSSL libssl-3.dll is not available for DTLS: {exc}") from exc
        try:
            self.crypto = ctypes.CDLL(str(find_libcrypto()))
        except OSError as exc:
            raise DtlsUnavailable(f"OpenSSL libcrypto-3.dll is not available for DTLS: {exc}") from exc

        self.ssl.DTLS_client_method.restype = ctypes.c_void_p
        self.ssl.SSL_CTX_new.argtypes = [ctypes.c_void_p]
        self.ssl.SSL_CTX_new.restype = ctypes.c_void_p
        self.ssl.SSL_CTX_free.argtypes = [ctypes.c_void_p]
        self.ssl.SSL_CTX_set_verify.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        self.ssl.SSL_CTX_set_options.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.ssl.SSL_CTX_set_options.restype = ctypes.c_ulong
        self.ssl.SSL_CTX_set_cipher_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.ssl.SSL_CTX_set_cipher_list.restype = ctypes.c_int
        self.ctx_set_min_proto_version = getattr(self.ssl, "SSL_CTX_set_min_proto_version", None)
        if self.ctx_set_min_proto_version is not None:
            self.ctx_set_min_proto_version.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.ctx_set_min_proto_version.restype = ctypes.c_int
        self.ctx_set_max_proto_version = getattr(self.ssl, "SSL_CTX_set_max_proto_version", None)
        if self.ctx_set_max_proto_version is not None:
            self.ctx_set_max_proto_version.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.ctx_set_max_proto_version.restype = ctypes.c_int
        self.ssl.SSL_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
        self.ssl.SSL_CTX_ctrl.restype = ctypes.c_long
        self.ctx_set_read_ahead = getattr(self.ssl, "SSL_CTX_set_read_ahead", None)
        if self.ctx_set_read_ahead is not None:
            self.ctx_set_read_ahead.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.ssl.SSL_new.argtypes = [ctypes.c_void_p]
        self.ssl.SSL_new.restype = ctypes.c_void_p
        self.ssl.SSL_free.argtypes = [ctypes.c_void_p]
        self.ssl.SSL_set_connect_state.argtypes = [ctypes.c_void_p]
        self.ssl.SSL_set_bio.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.ssl.SSL_do_handshake.argtypes = [ctypes.c_void_p]
        self.ssl.SSL_do_handshake.restype = ctypes.c_int
        self.ssl.SSL_get_error.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.ssl.SSL_get_error.restype = ctypes.c_int
        self.ssl.SSL_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        self.ssl.SSL_read.restype = ctypes.c_int
        self.ssl.SSL_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        self.ssl.SSL_write.restype = ctypes.c_int
        self.ssl_get_cipher = getattr(self.ssl, "SSL_get_cipher", None)
        if self.ssl_get_cipher is not None:
            self.ssl_get_cipher.argtypes = [ctypes.c_void_p]
            self.ssl_get_cipher.restype = ctypes.c_char_p
        try:
            self.crypto.BIO_new_dgram.argtypes = [ctypes.c_size_t, ctypes.c_int]
            self.crypto.BIO_new_dgram.restype = ctypes.c_void_p
        except AttributeError as exc:
            raise DtlsUnavailable("OpenSSL libcrypto-3.dll does not export BIO_new_dgram; Fortinet DTLS is unavailable with this DLL.") from exc
        self.crypto.BIO_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
        self.crypto.BIO_ctrl.restype = ctypes.c_long
        self.crypto.ERR_get_error.argtypes = []
        self.crypto.ERR_get_error.restype = ctypes.c_ulong
        self.crypto.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

    def error_queue_text(self) -> str:
        messages: list[str] = []
        while True:
            code = self.crypto.ERR_get_error()
            if not code:
                break
            buffer = ctypes.create_string_buffer(256)
            self.crypto.ERR_error_string_n(code, buffer, len(buffer))
            messages.append(buffer.value.decode("ascii", "replace"))
        return "; ".join(messages)


class SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


def find_libssl() -> Path | str:
    candidates: list[Path] = []
    executable = Path(sys.executable).resolve()
    candidates.extend(
        [
            executable.parent / "DLLs" / "libssl-3.dll",
            executable.parent / "libssl-3.dll",
            Path(__file__).resolve().parent.parent / "libssl-3.dll",
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            if hasattr(os, "add_dll_directory"):
                os.add_dll_directory(str(candidate.parent))
            return candidate
    return "libssl-3.dll"


def find_libcrypto() -> Path | str:
    candidates: list[Path] = []
    executable = Path(sys.executable).resolve()
    candidates.extend(
        [
            executable.parent / "DLLs" / "libcrypto-3.dll",
            executable.parent / "libcrypto-3.dll",
            Path(__file__).resolve().parent.parent / "libcrypto-3.dll",
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            if hasattr(os, "add_dll_directory"):
                os.add_dll_directory(str(candidate.parent))
            return candidate
    return "libcrypto-3.dll"


class OpenSslDtlsSocket:
    def __init__(self, api: OpenSslApi, udp: socket.socket, ctx, ssl_obj) -> None:
        self.api = api
        self.udp = udp
        self.ctx = ctx
        self.ssl_obj = ssl_obj

    def fileno(self) -> int:
        return self.udp.fileno()

    def setblocking(self, flag: bool) -> None:
        self.udp.setblocking(flag)

    def recv(self, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        ret = self.api.ssl.SSL_read(self.ssl_obj, buffer, size)
        if ret > 0:
            return buffer.raw[:ret]
        err = self.api.ssl.SSL_get_error(self.ssl_obj, ret)
        if err in (self.api.SSL_ERROR_WANT_READ, self.api.SSL_ERROR_WANT_WRITE):
            raise BlockingIOError()
        raise OSError(f"DTLS SSL_read failed with OpenSSL error {err}")

    class _WantRead(BlockingIOError):
        pass

    class _WantWrite(BlockingIOError):
        pass

    def send(self, data) -> int:
        chunk = bytes(data)
        buffer = ctypes.create_string_buffer(chunk)
        ret = self.api.ssl.SSL_write(self.ssl_obj, buffer, len(chunk))
        if ret > 0:
            return ret
        err = self.api.ssl.SSL_get_error(self.ssl_obj, ret)
        if err == self.api.SSL_ERROR_WANT_READ:
            raise self._WantRead()
        if err == self.api.SSL_ERROR_WANT_WRITE:
            raise self._WantWrite()
        raise OSError(f"DTLS SSL_write failed with OpenSSL error {err}")

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        sent = 0
        while sent < len(data):
            try:
                sent += self.send(view[sent:])
                continue
            except self._WantRead:
                select.select([self], [], [], 1.0)
                continue
            except self._WantWrite:
                select.select([], [self], [], 1.0)
                continue

    def close(self) -> None:
        self.api.ssl.SSL_free(self.ssl_obj)
        self.api.ssl.SSL_CTX_free(self.ctx)
        self.udp.close()


class FortinetDtlsTransport:
    def __init__(
        self,
        base_url: str,
        svpn_cookie: str,
        *,
        timeout: float = 10.0,
        verify_tls: bool = True,
        log=print,
    ) -> None:
        parsed = urlparse(base_url if "://" in base_url else "https://" + base_url)
        self.host = parsed.hostname or ""
        self.port = parsed.port or 443
        self.svpn_cookie = svpn_cookie
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.log = log
        self.api = OpenSslApi()
        self.sock: OpenSslDtlsSocket | None = None

    def open(self) -> OpenSslDtlsSocket:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(self.timeout)
        udp.connect((self.host, self.port))
        udp.setblocking(False)

        method = self.api.ssl.DTLS_client_method()
        ctx = self.api.ssl.SSL_CTX_new(method)
        if not ctx:
            udp.close()
            raise DtlsUnavailable("OpenSSL failed to create DTLS context")

        # OpenConnect verifies Fortinet HTTPS cert before this point. Full DTLS
        # certificate-chain verification through ctypes is future hardening.
        self.api.ssl.SSL_CTX_set_verify(ctx, self.api.SSL_VERIFY_NONE, None)
        if self.api.ctx_set_read_ahead is not None:
            self.api.ctx_set_read_ahead(ctx, 1)
        self._set_dtls12_bounds(ctx)
        self._set_fortinet_dtls_compat(ctx)

        ssl_obj = self.api.ssl.SSL_new(ctx)
        if not ssl_obj:
            self.api.ssl.SSL_CTX_free(ctx)
            udp.close()
            raise DtlsUnavailable("OpenSSL failed to create DTLS SSL object")

        bio = self.api.crypto.BIO_new_dgram(udp.fileno(), self.api.BIO_NOCLOSE)
        if not bio:
            self.api.ssl.SSL_free(ssl_obj)
            self.api.ssl.SSL_CTX_free(ctx)
            udp.close()
            raise DtlsUnavailable("OpenSSL failed to create DTLS datagram BIO")
        self._set_dgram_connected(bio, udp.getpeername())

        self.api.ssl.SSL_set_connect_state(ssl_obj)
        self.api.ssl.SSL_set_bio(ssl_obj, bio, bio)
        dtls_sock = OpenSslDtlsSocket(self.api, udp, ctx, ssl_obj)
        self._handshake(dtls_sock)
        self._authenticate_fortinet_dtls(dtls_sock)
        cipher = self.api.ssl_get_cipher(ssl_obj) if self.api.ssl_get_cipher is not None else None
        self.log("myvpn_tunnel DTLS established with OpenSSL: " + (cipher.decode("ascii", "replace") if cipher else "cipher unavailable"))
        self.sock = dtls_sock
        return dtls_sock

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def _set_fortinet_dtls_compat(self, ctx) -> None:
        options = (
            self.api.SSL_OP_NO_ENCRYPT_THEN_MAC
            | self.api.SSL_OP_NO_EXTENDED_MASTER_SECRET
            | self.api.SSL_OP_LEGACY_SERVER_CONNECT
        )
        self.api.ssl.SSL_CTX_set_options(ctx, options)
        if self.api.ssl.SSL_CTX_set_cipher_list(ctx, self.api.FORTINET_DTLS12_CIPHERS) != 1:
            detail = self.api.error_queue_text()
            suffix = f": {detail}" if detail else ""
            raise DtlsUnavailable(f"OpenSSL failed to set Fortinet DTLS cipher list{suffix}")

    def _set_dgram_connected(self, bio, peer: tuple) -> None:
        host = str(peer[0])
        port = int(peer[1])
        try:
            addr = (ctypes.c_ubyte * 4).from_buffer_copy(socket.inet_aton(host))
        except OSError as exc:
            raise DtlsUnavailable(f"OpenSSL DTLS peer address is not IPv4: {host}") from exc
        sockaddr = SockaddrIn(socket.AF_INET, socket.htons(port), addr, (ctypes.c_ubyte * 8)())
        if self.api.crypto.BIO_ctrl(bio, self.api.BIO_CTRL_DGRAM_SET_CONNECTED, 0, ctypes.byref(sockaddr)) <= 0:
            detail = self.api.error_queue_text()
            suffix = f": {detail}" if detail else ""
            raise DtlsUnavailable(f"OpenSSL failed to mark DTLS datagram BIO as connected{suffix}")

    def _set_dtls12_bounds(self, ctx) -> None:
        if self.api.ctx_set_min_proto_version is not None:
            self.api.ctx_set_min_proto_version(ctx, self.api.DTLS1_2_VERSION)
        else:
            self.api.ssl.SSL_CTX_ctrl(ctx, self.api.SSL_CTRL_SET_MIN_PROTO_VERSION, self.api.DTLS1_2_VERSION, None)
        if self.api.ctx_set_max_proto_version is not None:
            self.api.ctx_set_max_proto_version(ctx, self.api.DTLS1_2_VERSION)
        else:
            self.api.ssl.SSL_CTX_ctrl(ctx, self.api.SSL_CTRL_SET_MAX_PROTO_VERSION, self.api.DTLS1_2_VERSION, None)

    def _handshake(self, dtls_sock: OpenSslDtlsSocket) -> None:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            ret = self.api.ssl.SSL_do_handshake(dtls_sock.ssl_obj)
            if ret == 1:
                return
            err = self.api.ssl.SSL_get_error(dtls_sock.ssl_obj, ret)
            if err == self.api.SSL_ERROR_WANT_READ:
                select.select([dtls_sock], [], [], 0.5)
                continue
            if err == self.api.SSL_ERROR_WANT_WRITE:
                select.select([], [dtls_sock], [], 0.5)
                continue
            detail = self.api.error_queue_text()
            suffix = f": {detail}" if detail else ""
            raise DtlsUnavailable(f"OpenSSL DTLS handshake failed with error {err}{suffix}")
        raise DtlsUnavailable("OpenSSL DTLS handshake timed out")

    def _authenticate_fortinet_dtls(self, dtls_sock: OpenSslDtlsSocket) -> None:
        hello = build_fortinet_dtls_client_hello(self.svpn_cookie)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            dtls_sock.sendall(hello)
            ready, _, _ = select.select([dtls_sock], [], [], 1.0)
            if not ready:
                continue
            try:
                packet = dtls_sock.recv(4096)
            except BlockingIOError:
                continue
            if parse_fortinet_dtls_server_hello(packet):
                return
        raise DtlsUnavailable("Fortinet DTLS svrhello authentication timed out")

