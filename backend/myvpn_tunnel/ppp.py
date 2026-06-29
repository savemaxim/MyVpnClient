from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import ipaddress
import queue
import random
import select
import socket
import ssl
import struct
import time


PPP_LCP = 0xC021
PPP_IPCP = 0x8021
PPP_IP = 0x0021
PPP_IP6 = 0x0057

CONFREQ = 1
CONFACK = 2
CONFNAK = 3
CONFREJ = 4
TERMREQ = 5
TERMACK = 6
ECHOREQ = 9
ECHOREP = 10
DISCREQ = 11

LCP_MRU = 1
LCP_ASYNCMAP = 2
LCP_AUTH = 3
LCP_MAGIC = 5
LCP_PFCOMP = 7
LCP_ACCOMP = 8
IPCP_IPADDR = 3
IPCP_IPCOMP = 2
IPCP_DNS0 = 129
IPCP_DNS1 = 131


@dataclass
class PppState:
    mtu: int = 1351
    magic: int = field(default_factory=lambda: random.getrandbits(32))
    lcp_id: int = 0
    ipcp_id: int = 0
    lcp_request_body: bytes = b""
    ipcp_request_body: bytes = b""
    lcp_outstanding_ids: set[int] = field(default_factory=set)
    ipcp_outstanding_ids: set[int] = field(default_factory=set)
    pending_ipcp_confreq_id: int | None = None
    pending_ipcp_confreq_body: bytes = b""
    peer_ipcp_confreq_id: int | None = None
    peer_ipcp_confreq_body: bytes = b""
    lcp_ack_sent: bool = False
    lcp_ack_received: bool = False
    ipcp_ack_sent: bool = False
    ipcp_ack_received: bool = False
    ipv4: str = "0.0.0.0"
    dns: list[str] = field(default_factory=list)
    request_ipv4: bool = True
    request_dns: bool = False
    phase: str = "lcp-start"
    phase_since: float = field(default_factory=time.monotonic)
    last_rx: float = field(default_factory=time.monotonic)
    last_tx: float = field(default_factory=time.monotonic)
    rx_packets: int = 0
    tx_packets: int = 0
    rx_ip_packets: int = 0
    tx_ip_packets: int = 0
    rx_udp53_packets: int = 0
    tx_udp53_packets: int = 0
    rx_udp53_logged: int = 0
    tx_udp53_logged: int = 0
    rx_flow_logged: int = 0
    tx_flow_logged: int = 0

    @property
    def network_ready(self) -> bool:
        return self.lcp_ack_sent and self.lcp_ack_received and self.ipcp_ack_sent and self.ipcp_ack_received


class FortinetPppEngine:
    def __init__(
        self,
        sock,
        *,
        tap=None,
        log=print,
        mtu: int = 1351,
        routes: list[str] | None = None,
        dns: list[str] | None = None,
        metric: int = 1,
        on_ready=None,
        on_phase=None,
        on_stats=None,
        on_packet=None,
        trace_flows: bool = False,
        fast_data_path: bool = True,
        max_coalesce_frames: int = 32,
        max_coalesce_bytes: int = 64 * 1024,
        negotiation_timeout: float = 90.0,
        idle_timeout: float = 0.0,
        terminate_grace: float = 2.0,
    ) -> None:
        self.sock = sock
        self.tap = tap
        self.log = log
        self.routes = routes or []
        self.dns = dns or []
        self.metric = metric
        self.on_ready = on_ready
        self.on_phase = on_phase
        self.on_stats = on_stats
        self.on_packet = on_packet
        self.trace_flows = trace_flows
        self.fast_data_path = fast_data_path
        self.max_coalesce_frames = max(1, int(max_coalesce_frames or 1))
        self.max_coalesce_bytes = max(4096, int(max_coalesce_bytes or 4096))
        self.tx_socket_writes = 0
        self.tx_coalesced_frames = 0
        self.wake_r: socket.socket | None = None
        self.wake_w: socket.socket | None = None
        self.negotiation_timeout = negotiation_timeout
        self.idle_timeout = idle_timeout
        self.terminate_grace = terminate_grace
        self.state = PppState(mtu=mtu)
        self.rx_buffer = bytearray()
        self.outgoing: deque[tuple[int, bytes]] = deque()
        self.tap_queue: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self.tap_started = False
        self.ready_notified = False
        self.last_lcp_request = 0.0
        self.last_ipcp_request = 0.0
        self.last_keepalive = 0.0
        self.last_stats = 0.0
        self.open_wake_pair()
        self.log(f"myvpn_tunnel PPP module path: {__file__}")

    def run(self, *, should_stop) -> int:
        self.sock.setblocking(False)
        self.set_phase("lcp-start", "Starting LCP negotiation.")
        self.queue_lcp_request()
        self.log("myvpn_tunnel PPP negotiation started.")

        try:
            while not should_stop():
                now = time.monotonic()
                self.tick_negotiation(now)
                self.tick_stats(now)
                did_work = 0
                self.drain_wake()
                try:
                    did_work += self.pump_tls_input(timeout=0.0)
                except Exception as exc:
                    self.log(f"myvpn_tunnel PPP tunnel failed: {exc}")
                    return 2

                did_work += self.drain_tap_queue()
                try:
                    did_work += self.flush_outgoing()
                except Exception as exc:
                    self.log(f"myvpn_tunnel PPP send failed: {exc}")
                    return 2

                if not self.state.network_ready and now - self.state.phase_since > self.negotiation_timeout:
                    self.set_phase("negotiation-timeout", f"PPP phase {self.state.phase} timed out after {self.negotiation_timeout:.0f}s.")
                    self.log(f"myvpn_tunnel PPP negotiation timed out in phase {self.state.phase}.")
                    return 3

                if self.state.network_ready and self.idle_timeout > 0:
                    idle_for = now - max(self.state.last_rx, self.state.last_tx)
                    if idle_for > self.idle_timeout:
                        self.set_phase("tunnel-stalled", f"No tunnel traffic for {idle_for:.0f}s.")
                        self.log(f"myvpn_tunnel PPP tunnel stalled; no RX/TX for {idle_for:.0f}s.")
                        return 4

                if did_work:
                    continue

                try:
                    self.wait_for_activity(self.idle_wait_seconds(now))
                except ConnectionResetError:
                    return 1
                except Exception as exc:
                    self.log(f"myvpn_tunnel PPP tunnel failed: {exc}")
                    return 2

            self.log("myvpn_tunnel PPP stopped by owner/disconnect request.")
            self.graceful_terminate()
            return 0
        finally:
            self.close_wake_pair()

    def open_wake_pair(self) -> None:
        try:
            self.wake_r, self.wake_w = socket.socketpair()
            self.wake_r.setblocking(False)
            self.wake_w.setblocking(False)
        except OSError as exc:
            self.wake_r = None
            self.wake_w = None
            self.log(f"myvpn_tunnel PPP wake socket unavailable; using short polling fallback: {exc}")

    def close_wake_pair(self) -> None:
        for sock in (self.wake_r, self.wake_w):
            if sock is None:
                continue
            try:
                sock.close()
            except OSError:
                pass
        self.wake_r = None
        self.wake_w = None

    def notify_tap_packet(self) -> None:
        if self.wake_w is None:
            return
        try:
            self.wake_w.send(b"\x00")
        except (BlockingIOError, OSError):
            pass

    def drain_wake(self) -> int:
        if self.wake_r is None:
            return 0
        drained = 0
        while True:
            try:
                data = self.wake_r.recv(4096)
            except BlockingIOError:
                return drained
            except OSError:
                return drained
            if not data:
                return drained
            drained += len(data)

    def idle_wait_seconds(self, now: float) -> float:
        deadlines: list[float] = []
        if not self.state.network_ready:
            deadlines.append(self.state.phase_since + self.negotiation_timeout)
            deadlines.append(self.last_lcp_request + 3.0)
            if self.state.lcp_ack_sent and self.state.lcp_ack_received:
                deadlines.append(self.last_ipcp_request + 3.0)
        else:
            deadlines.append(self.last_keepalive + 30.0)
            if self.idle_timeout > 0:
                deadlines.append(max(self.state.last_rx, self.state.last_tx) + self.idle_timeout)
        if self.on_stats:
            deadlines.append(self.last_stats + 5.0)
        if not deadlines:
            return 0.25 if self.wake_r is not None else 0.005
        delay = min(deadlines) - now
        ceiling = 1.0 if self.wake_r is not None else 0.005
        return max(0.001, min(ceiling, delay))

    def wait_for_activity(self, timeout: float) -> int:
        sockets = [self.sock]
        if self.wake_r is not None:
            sockets.append(self.wake_r)
        readable, _, exceptional = select.select(sockets, [], [self.sock], timeout)
        if exceptional:
            self.log("myvpn_tunnel PPP TLS socket reported an exceptional state.")
            raise ConnectionError("TLS socket exceptional state")
        processed = 0
        if self.wake_r is not None and self.wake_r in readable:
            processed += self.drain_wake()
        if self.sock in readable:
            processed += self.pump_tls_input(timeout=0.0)
        return processed

    def pump_tls_input(self, *, timeout: float) -> int:
        processed = 0
        wait = timeout
        while True:
            if wait > 0:
                readable, _, exceptional = select.select([self.sock], [], [self.sock], wait)
                if exceptional:
                    self.log("myvpn_tunnel PPP TLS socket reported an exceptional state.")
                    raise ConnectionError("TLS socket exceptional state")
                if not readable:
                    return processed
            try:
                chunk = self.sock.recv(65536)
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                return processed
            if not chunk:
                self.log("myvpn_tunnel PPP tunnel socket closed by server.")
                raise ConnectionResetError("TLS socket closed")
            self.rx_buffer.extend(chunk)
            self.state.last_rx = time.monotonic()
            processed += self.process_rx_buffer()
            wait = 0.0

    def set_phase(self, phase: str, detail: str = "") -> None:
        if self.state.phase == phase:
            return
        self.state.phase = phase
        self.state.phase_since = time.monotonic()
        self.log(f"myvpn_tunnel PPP phase: {phase}" + (f" - {detail}" if detail else ""))
        if self.on_phase:
            self.on_phase(phase, detail)

    def tick_stats(self, now: float) -> None:
        if not self.on_stats or now - self.last_stats < 5:
            return
        self.last_stats = now
        self.on_stats(
            {
                "phase": self.state.phase,
                "rxPackets": self.state.rx_packets,
                "txPackets": self.state.tx_packets,
                "rxIpPackets": self.state.rx_ip_packets,
                "txIpPackets": self.state.tx_ip_packets,
                "rxUdp53Packets": self.state.rx_udp53_packets,
                "txUdp53Packets": self.state.tx_udp53_packets,
                "lastRxSecondsAgo": max(0, int(now - self.state.last_rx)),
                "lastTxSecondsAgo": max(0, int(now - self.state.last_tx)),
                "tapQueue": self.tap_queue.qsize(),
                "outgoingQueue": len(self.outgoing),
                "rxBufferBytes": len(self.rx_buffer),
                "fastDataPath": self.fast_data_path,
                "txSocketWrites": self.tx_socket_writes,
                "txCoalescedFrames": self.tx_coalesced_frames,
            }
        )

    def tick_negotiation(self, now: float) -> None:
        if not self.state.lcp_ack_received and now - self.last_lcp_request >= 3:
            self.queue_lcp_request(retransmit=True)

        if self.state.lcp_ack_sent and self.state.lcp_ack_received:
            if not self.state.ipcp_ack_received and self.state.phase in {"lcp-start", "lcp-opened"}:
                self.set_phase("ipcp-start", "LCP is open; starting IPCP.")
            if not self.state.ipcp_ack_received and now - self.last_ipcp_request >= 3:
                self.queue_peer_ipcp_ack()
                self.queue_ipcp_request(retransmit=True)

        if self.state.network_ready:
            if self.state.phase != "network-ready":
                self.set_phase("network-ready", f"PPP negotiation complete; IPv4={self.state.ipv4}.")
            if self.tap and not self.tap_started:
                self.tap.configure(
                    self.state.ipv4,
                    routes=self.routes,
                    dns=self.dns or self.state.dns,
                    metric=self.metric,
                    mtu=self.state.mtu,
                )
                try:
                    self.tap.start_reader(self.tap_queue, notify=self.notify_tap_packet)
                except TypeError as exc:
                    if "notify" not in str(exc):
                        raise
                    self.tap.start_reader(self.tap_queue)
                self.tap_started = True
                self.log(f"myvpn_tunnel TAP reader started; assigned IPv4 {self.state.ipv4}.")
            if not self.ready_notified:
                self.ready_notified = True
                if self.on_ready:
                    self.on_ready(self.state.ipv4)
            if now - self.last_keepalive >= 30:
                self.last_keepalive = now
                self.queue_control(PPP_LCP, DISCREQ, self.next_lcp_id(), b"")

    def process_rx_buffer(self) -> int:
        processed = 0
        while True:
            if len(self.rx_buffer) < 6:
                return processed
            if self.rx_buffer.startswith(b"HTTP/"):
                response = bytes(self.rx_buffer[: min(len(self.rx_buffer), 2048)])
                raise ConnectionError(
                    "Fortinet tunnel request was rejected: "
                    + response.decode("iso-8859-1", errors="replace").split("\r\n", 1)[0]
                )
            total_len, magic, payload_len = struct.unpack(">HHH", self.rx_buffer[:6])
            if magic != 0x5050 or total_len != payload_len + 6:
                raise ValueError(f"Unexpected Fortinet PPP header total={total_len} magic=0x{magic:04x} payload={payload_len}")
            if len(self.rx_buffer) < total_len:
                return processed
            frame = bytes(self.rx_buffer[6:total_len])
            del self.rx_buffer[:total_len]
            self.state.rx_packets += 1
            processed += 1
            self.handle_ppp_frame(frame)

    def handle_ppp_frame(self, frame: bytes) -> None:
        proto, payload = parse_ppp_frame(frame)
        if proto in (PPP_LCP, PPP_IPCP):
            self.handle_control(proto, payload)
        elif proto == PPP_IP:
            self.state.rx_ip_packets += 1
            if is_udp53_packet(payload):
                self.state.rx_udp53_packets += 1
                self.emit_dns_packet("rx", payload)
            self.emit_flow_packet("rx", payload)
            if self.tap and self.tap_started:
                written = self.tap.write(payload)
                if self.trace_flows:
                    summary = describe_flow_packet(payload)
                    if summary and (summary.get("flowKind") == "tcp" or summary.get("ipProto") == 6):
                        tap_summary = dict(summary)
                        tap_summary["tapWriteBytes"] = written
                        tap_summary["packetBytes"] = len(payload)
                        if self.on_packet:
                            self.on_packet("tap-write", tap_summary)
                        else:
                            self.log(f"myvpn_tunnel TAP write {written}/{len(payload)} bytes: {tap_summary}")
            else:
                self.log(f"myvpn_tunnel received IPv4 packet before TAP ready ({len(payload)} bytes).")
        elif proto == PPP_IP6:
            self.log("myvpn_tunnel received IPv6 packet; IPv6 routing is not implemented yet.")
        else:
            self.log(f"myvpn_tunnel ignoring PPP protocol 0x{proto:04x} ({len(payload)} bytes).")

    def handle_control(self, proto: int, payload: bytes) -> None:
        if len(payload) < 4:
            return
        code, ident, length = struct.unpack(">BBH", payload[:4])
        body = payload[4:length]
        name = "LCP" if proto == PPP_LCP else "IPCP"
        self.log(f"myvpn_tunnel PPP {name} code={code} id={ident} len={length}")

        if code == CONFREQ:
            self.handle_confreq(proto, ident, body)
        elif code == CONFACK:
            if proto == PPP_LCP and ident in self.state.lcp_outstanding_ids:
                self.state.lcp_ack_received = True
                self.log("myvpn_tunnel LCP config acknowledged.")
                if self.state.lcp_ack_sent:
                    self.open_lcp()
            elif proto == PPP_IPCP and ident in self.state.ipcp_outstanding_ids:
                self.state.ipcp_ack_received = True
                self.log(f"myvpn_tunnel IPCP config acknowledged; IPv4={self.state.ipv4}.")
        elif code == CONFNAK:
            self.handle_confnak(proto, ident, body)
        elif code == CONFREJ:
            self.log(f"myvpn_tunnel PPP {name} config rejected; retrying with minimal options.")
            if proto == PPP_LCP:
                self.state.lcp_ack_received = False
                self.queue_lcp_request(minimal=True)
            elif proto == PPP_IPCP:
                for tag, _ in iter_options(body):
                    if tag == IPCP_IPADDR:
                        self.state.request_ipv4 = False
                        self.log("myvpn_tunnel server rejected IPCP IPv4 option; retrying without address request.")
                    elif tag in (IPCP_DNS0, IPCP_DNS1):
                        self.state.request_dns = False
                        self.log("myvpn_tunnel server rejected IPCP DNS option; retrying without DNS request.")
                self.queue_ipcp_request()
        elif code == ECHOREQ and proto == PPP_LCP:
            self.queue_control(PPP_LCP, ECHOREP, ident, body)
        elif code == TERMREQ:
            self.queue_control(proto, TERMACK, ident, body)

    def handle_confreq(self, proto: int, ident: int, body: bytes) -> None:
        if proto == PPP_LCP:
            ack_body = bytearray()
            rej_body = bytearray()
            for raw, tag, value in iter_raw_options(body):
                if tag == LCP_MRU and len(value) == 2:
                    self.state.mtu = min(self.state.mtu, struct.unpack(">H", value)[0])
                    ack_body.extend(raw)
                elif tag == LCP_MAGIC and len(value) == 4:
                    ack_body.extend(raw)
                else:
                    rej_body.extend(raw)
            if rej_body:
                rejected = ", ".join(str(tag) for _raw, tag, _value in iter_raw_options(bytes(rej_body)))
                self.log(f"myvpn_tunnel rejected unsupported LCP option(s): {rejected}.")
                self.queue_control(PPP_LCP, CONFREJ, ident, bytes(rej_body))
                return
            self.state.lcp_ack_sent = True
            self.queue_control(PPP_LCP, CONFACK, ident, bytes(ack_body))
            if self.state.lcp_ack_received:
                self.open_lcp()
            return
        elif proto == PPP_IPCP:
            ack_body = bytearray()
            rej_body = bytearray()
            for raw, tag, value in iter_raw_options(body):
                if tag in (IPCP_IPADDR, IPCP_DNS0, IPCP_DNS1) and len(value) == 4:
                    ack_body.extend(raw)
                else:
                    rej_body.extend(raw)
            if rej_body:
                rejected = ", ".join(str(tag) for _raw, tag, _value in iter_raw_options(bytes(rej_body)))
                self.log(f"myvpn_tunnel rejected unsupported IPCP option(s): {rejected}.")
                self.queue_control(PPP_IPCP, CONFREJ, ident, bytes(rej_body))
                return
            self.state.peer_ipcp_confreq_id = ident
            self.state.peer_ipcp_confreq_body = bytes(ack_body)
            if not (self.state.lcp_ack_sent and self.state.lcp_ack_received):
                self.state.pending_ipcp_confreq_id = ident
                self.state.pending_ipcp_confreq_body = bytes(ack_body)
                self.log("myvpn_tunnel deferring IPCP config request until LCP is open.")
                return
            self.state.ipcp_ack_sent = True
            self.queue_control(PPP_IPCP, CONFACK, ident, bytes(ack_body))
            return
        self.queue_control(proto, CONFACK, ident, body)

    def open_lcp(self) -> None:
        if self.state.phase == "lcp-start":
            self.set_phase("lcp-opened", "LCP config acknowledged by both peers.")
        if self.state.pending_ipcp_confreq_id is not None:
            self.state.ipcp_ack_sent = True
            self.queue_control(
                PPP_IPCP,
                CONFACK,
                self.state.pending_ipcp_confreq_id,
                self.state.pending_ipcp_confreq_body,
            )
            self.state.pending_ipcp_confreq_id = None
            self.state.pending_ipcp_confreq_body = b""

    def queue_peer_ipcp_ack(self) -> None:
        if self.state.peer_ipcp_confreq_id is None:
            return
        self.state.ipcp_ack_sent = True
        self.queue_control(PPP_IPCP, CONFACK, self.state.peer_ipcp_confreq_id, self.state.peer_ipcp_confreq_body)

    def handle_confnak(self, proto: int, ident: int, body: bytes) -> None:
        if proto == PPP_IPCP and ident in self.state.ipcp_outstanding_ids:
            for tag, value in iter_options(body):
                if tag == IPCP_IPADDR and len(value) == 4:
                    self.state.ipv4 = str(ipaddress.IPv4Address(value))
                    self.log(f"myvpn_tunnel server offered IPv4 {self.state.ipv4}.")
                elif tag in (IPCP_DNS0, IPCP_DNS1) and len(value) == 4:
                    dns = str(ipaddress.IPv4Address(value))
                    if dns != "0.0.0.0" and dns not in self.state.dns:
                        self.state.dns.append(dns)
                        self.log(f"myvpn_tunnel server offered DNS {dns}.")
            self.queue_ipcp_request()
        elif proto == PPP_LCP and ident in self.state.lcp_outstanding_ids:
            self.queue_lcp_request(minimal=True)

    def queue_lcp_request(self, *, minimal: bool = False, retransmit: bool = False) -> None:
        self.last_lcp_request = time.monotonic()
        options = bytearray()
        options.extend(option(LCP_MRU, struct.pack(">H", self.state.mtu)))
        if not minimal:
            options.extend(option(LCP_MAGIC, struct.pack(">I", self.state.magic)))
        self.state.lcp_id = self.next_lcp_id()
        self.state.lcp_outstanding_ids.add(self.state.lcp_id)
        self.state.lcp_request_body = bytes(options)
        self.queue_control(PPP_LCP, CONFREQ, self.state.lcp_id, self.state.lcp_request_body)

    def queue_lcp_terminate(self) -> None:
        self.state.lcp_id = self.next_lcp_id()
        self.queue_control(PPP_LCP, TERMREQ, self.state.lcp_id, b"")

    def queue_ipcp_request(self, *, retransmit: bool = False) -> None:
        self.last_ipcp_request = time.monotonic()
        options = bytearray()
        if self.state.request_ipv4:
            options.extend(option(IPCP_IPADDR, ipaddress.IPv4Address(self.state.ipv4).packed))
        if self.state.request_dns and not self.state.dns:
            options.extend(option(IPCP_DNS0, b"\x00\x00\x00\x00"))
            options.extend(option(IPCP_DNS1, b"\x00\x00\x00\x00"))
        self.state.ipcp_id = self.next_ipcp_id()
        self.state.ipcp_outstanding_ids.add(self.state.ipcp_id)
        self.state.ipcp_request_body = bytes(options)
        self.queue_control(PPP_IPCP, CONFREQ, self.state.ipcp_id, self.state.ipcp_request_body)

    def queue_control(self, proto: int, code: int, ident: int, body: bytes) -> None:
        payload = struct.pack(">BBH", code, ident, len(body) + 4) + body
        self.outgoing.append((proto, payload))

    def emit_dns_packet(self, direction: str, packet: bytes) -> None:
        if direction == "rx":
            if self.state.rx_udp53_logged >= 12:
                return
            self.state.rx_udp53_logged += 1
        else:
            if self.state.tx_udp53_logged >= 12:
                return
            self.state.tx_udp53_logged += 1
        summary = describe_udp53_packet(packet)
        if not summary:
            return
        if self.on_packet:
            self.on_packet(direction, summary)
        else:
            self.log(
                "myvpn_tunnel dns_packet "
                f"{direction} {summary.get('src')}:{summary.get('srcPort')} -> "
                f"{summary.get('dst')}:{summary.get('dstPort')} "
                f"id={summary.get('dnsId')} qr={summary.get('qr')} rcode={summary.get('rcode')}"
            )

    def emit_flow_packet(self, direction: str, packet: bytes) -> None:
        if not self.trace_flows:
            return
        summary = describe_flow_packet(packet)
        if not summary:
            return
        if direction == "rx":
            if self.state.rx_flow_logged >= 80:
                return
            self.state.rx_flow_logged += 1
        else:
            if self.state.tx_flow_logged >= 80:
                return
            self.state.tx_flow_logged += 1
        if self.on_packet:
            self.on_packet(direction, summary)
        else:
            self.log(
                "myvpn_tunnel flow_packet "
                f"{direction} {summary.get('src')}:{summary.get('srcPort')} -> "
                f"{summary.get('dst')}:{summary.get('dstPort')} "
                f"proto={summary.get('ipProto')} flags={summary.get('tcpFlags')}"
            )

    def drain_tap_queue(self, *, max_packets: int | None = None) -> int:
        drained = 0
        get_nowait = self.tap_queue.get_nowait
        append_outgoing = self.outgoing.append
        state = self.state
        while max_packets is None or drained < max_packets:
            try:
                packet = get_nowait()
            except queue.Empty:
                return drained
            drained += 1
            proto = PPP_IP6 if packet and packet[0] >> 4 == 6 else PPP_IP
            if proto == PPP_IP:
                state.tx_ip_packets += 1
                if is_udp53_packet(packet):
                    state.tx_udp53_packets += 1
                    self.emit_dns_packet("tx", packet)
                self.emit_flow_packet("tx", packet)
            append_outgoing((proto, packet))
        return drained

    def flush_outgoing(self, *, max_frames: int | None = None) -> int:
        if self.fast_data_path and self.state.network_ready:
            return self.flush_outgoing_coalesced(max_frames=max_frames)

        flushed = 0
        while self.outgoing and (max_frames is None or flushed < max_frames):
            proto, payload = self.outgoing.popleft()
            if proto in (PPP_LCP, PPP_IPCP) and len(payload) >= 4:
                code, ident, length = struct.unpack(">BBH", payload[:4])
                name = "LCP" if proto == PPP_LCP else "IPCP"
                self.log(f"myvpn_tunnel PPP send {name} code={code} id={ident} len={length}")
            ppp_frame = build_ppp_frame(proto, payload)
            fortinet_frame = struct.pack(">HHH", len(ppp_frame) + 6, 0x5050, len(ppp_frame)) + ppp_frame
            self.sendall(fortinet_frame)
            self.tx_socket_writes += 1
            flushed += 1
            self.state.tx_packets += 1
            self.state.last_tx = time.monotonic()
        if self.on_stats:
            self.tick_stats(time.monotonic())
        return flushed

    def flush_outgoing_coalesced(self, *, max_frames: int | None = None) -> int:
        flushed = 0
        batch = bytearray()
        batch_frames = 0
        frame_limit = self.max_coalesce_frames if max_frames is None else max(1, min(self.max_coalesce_frames, max_frames))
        while self.outgoing and flushed < frame_limit:
            proto, payload = self.outgoing[0]
            if proto in (PPP_LCP, PPP_IPCP) and len(payload) >= 4:
                if batch:
                    break
                proto, payload = self.outgoing.popleft()
                code, ident, length = struct.unpack(">BBH", payload[:4])
                name = "LCP" if proto == PPP_LCP else "IPCP"
                self.log(f"myvpn_tunnel PPP send {name} code={code} id={ident} len={length}")
                ppp_frame = build_ppp_frame(proto, payload)
                batch.extend(struct.pack(">HHH", len(ppp_frame) + 6, 0x5050, len(ppp_frame)) + ppp_frame)
                flushed += 1
                batch_frames += 1
                break

            ppp_frame = build_ppp_frame(proto, payload)
            fortinet_frame = struct.pack(">HHH", len(ppp_frame) + 6, 0x5050, len(ppp_frame)) + ppp_frame
            if batch and len(batch) + len(fortinet_frame) > self.max_coalesce_bytes:
                break
            self.outgoing.popleft()
            batch.extend(fortinet_frame)
            flushed += 1
            batch_frames += 1

        if not batch:
            return 0
        self.sendall(bytes(batch))
        self.tx_socket_writes += 1
        if batch_frames > 1:
            self.tx_coalesced_frames += batch_frames
        now = time.monotonic()
        self.state.tx_packets += batch_frames
        self.state.last_tx = now
        if self.on_stats:
            self.tick_stats(now)
        return flushed

    def graceful_terminate(self) -> None:
        try:
            self.set_phase("terminating", "Sending PPP LCP terminate request.")
            self.queue_lcp_terminate()
            self.flush_outgoing()
            deadline = time.monotonic() + self.terminate_grace
            while time.monotonic() < deadline:
                readable, _, _ = select.select([self.sock], [], [], 0.25)
                if not readable:
                    continue
                try:
                    chunk = self.sock.recv(65536)
                except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    continue
                if not chunk:
                    break
                self.rx_buffer.extend(chunk)
                self.state.last_rx = time.monotonic()
                before = len(self.rx_buffer)
                self.process_rx_buffer()
                if len(self.rx_buffer) == before:
                    break
            self.log("myvpn_tunnel sent PPP LCP terminate request.")
        except Exception as exc:
            self.log(f"myvpn_tunnel PPP terminate request failed: {exc}")

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        sent = 0
        while sent < len(data):
            try:
                written = self.sock.send(view[sent:])
                if written == 0:
                    raise ConnectionError("TLS tunnel socket closed during PPP send")
                sent += written
            except (BlockingIOError, ssl.SSLWantReadError):
                select.select([self.sock], [], [], 1.0)
            except ssl.SSLWantWriteError:
                select.select([], [self.sock], [], 1.0)

    def next_lcp_id(self) -> int:
        self.state.lcp_id = (self.state.lcp_id + 1) & 0xFF
        return self.state.lcp_id or self.next_lcp_id()

    def next_ipcp_id(self) -> int:
        self.state.ipcp_id = (self.state.ipcp_id + 1) & 0xFF
        return self.state.ipcp_id or self.next_ipcp_id()



def checksum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def checksum_valid(data: bytes) -> bool:
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (total & 0xFFFF) == 0xFFFF


def describe_flow_packet(packet: bytes) -> dict | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        return None
    total_len = struct.unpack(">H", packet[2:4])[0]
    if total_len <= 0 or total_len > len(packet):
        total_len = len(packet)
    ip_proto = packet[9]
    src = str(ipaddress.IPv4Address(packet[12:16]))
    dst = str(ipaddress.IPv4Address(packet[16:20]))
    body = packet[ihl:total_len]
    result = {
        "src": src,
        "dst": dst,
        "ipProto": ip_proto,
        "ipLength": total_len,
        "ipChecksum": struct.unpack(">H", packet[10:12])[0],
        "ipChecksumOk": checksum_valid(packet[:ihl]),
    }
    if ip_proto == 6 and len(body) >= 20:
        src_port, dst_port, seq, ack, off_flags, window, tcp_sum, urgent = struct.unpack(">HHIIHHHH", body[:20])
        data_offset = ((off_flags >> 12) & 0xF) * 4
        flags = off_flags & 0x1FF
        flag_names = [
            name
            for bit, name in (
                (0x001, "FIN"),
                (0x002, "SYN"),
                (0x004, "RST"),
                (0x008, "PSH"),
                (0x010, "ACK"),
                (0x020, "URG"),
                (0x040, "ECE"),
                (0x080, "CWR"),
                (0x100, "NS"),
            )
            if flags & bit
        ]
        pseudo = packet[12:20] + bytes([0, ip_proto]) + struct.pack(">H", len(body))
        result.update({
            "flowKind": "tcp",
            "srcPort": src_port,
            "dstPort": dst_port,
            "tcpFlags": flags,
            "tcpFlagNames": flag_names,
            "tcpSeq": seq,
            "tcpAck": ack,
            "tcpWindow": window,
            "tcpChecksum": tcp_sum,
            "tcpChecksumOk": checksum_valid(pseudo + body),
            "tcpHeaderLength": data_offset,
        })
    elif ip_proto == 17 and len(body) >= 8:
        src_port, dst_port, udp_len, udp_sum = struct.unpack(">HHHH", body[:8])
        pseudo = packet[12:20] + bytes([0, ip_proto]) + struct.pack(">H", len(body))
        result.update({
            "flowKind": "udp",
            "srcPort": src_port,
            "dstPort": dst_port,
            "udpLength": udp_len,
            "udpChecksum": udp_sum,
            "udpChecksumOk": udp_sum == 0 or checksum_valid(pseudo + body),
        })
    else:
        return None
    interesting = result.get("flowKind") == "tcp" and (
        result.get("dstPort") == 443
        or result.get("srcPort") == 443
    )
    return result if interesting else None


def describe_udp53_packet(packet: bytes) -> dict | None:
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if len(packet) < ihl + 20 or packet[9] != 17:
        return None
    src_port, dst_port, udp_len = struct.unpack('>HHH', packet[ihl:ihl + 6])
    if src_port != 53 and dst_port != 53:
        return None
    dns_offset = ihl + 8
    base = {
        "src": str(ipaddress.IPv4Address(packet[12:16])),
        "dst": str(ipaddress.IPv4Address(packet[16:20])),
        "srcPort": src_port,
        "dstPort": dst_port,
        "udpLength": udp_len,
        "ipLength": struct.unpack('>H', packet[2:4])[0],
    }
    base["dnsHex"] = packet[dns_offset:dns_offset + 96].hex()
    if len(packet) < dns_offset + 12:
        return base
    dns_id, flags, qd, an, ns, ar = struct.unpack('>HHHHHH', packet[dns_offset:dns_offset + 12])
    result = {
        **base,
        "dnsId": dns_id,
        "qr": (flags >> 15) & 1,
        "opcode": (flags >> 11) & 0xF,
        "rcode": flags & 0xF,
        "questions": qd,
        "answers": an,
        "authority": ns,
        "additional": ar,
    }
    msg = packet[dns_offset:]
    cursor = 12
    question_names: list[str] = []
    question_types: list[int] = []
    for _ in range(qd):
        name, cursor = read_dns_name(msg, cursor)
        if name:
            question_names.append(name)
        if cursor + 4 > len(msg):
            return result | {"qname": ",".join(question_names)}
        qtype, _qclass = struct.unpack('>HH', msg[cursor:cursor + 4])
        question_types.append(qtype)
        cursor += 4
    if question_names:
        result["qname"] = ",".join(question_names)
    if question_types:
        result["qtype"] = ",".join(str(item) for item in question_types)
    answer_a: list[str] = []
    for _ in range(an):
        _name, cursor = read_dns_name(msg, cursor)
        if cursor + 10 > len(msg):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack('>HHIH', msg[cursor:cursor + 10])
        cursor += 10
        rdata = msg[cursor:cursor + rdlen]
        cursor += rdlen
        if rtype == 1 and rdlen == 4:
            answer_a.append(str(ipaddress.IPv4Address(rdata)))
    if answer_a:
        result["answerA"] = ",".join(answer_a)
    return result


def read_dns_name(message: bytes, offset: int, *, depth: int = 0) -> tuple[str, int]:
    if depth > 8:
        return "", offset
    labels: list[str] = []
    cursor = offset
    jumped = False
    end_offset = offset
    while cursor < len(message):
        length = message[cursor]
        if length == 0:
            cursor += 1
            if not jumped:
                end_offset = cursor
            return ".".join(labels), end_offset
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                return ".".join(labels), len(message)
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            suffix, _ = read_dns_name(message, pointer, depth=depth + 1)
            if suffix:
                labels.append(suffix)
            if not jumped:
                end_offset = cursor + 2
            return ".".join(labels), end_offset
        cursor += 1
        if cursor + length > len(message):
            return ".".join(labels), len(message)
        labels.append(message[cursor:cursor + length].decode('ascii', 'replace'))
        cursor += length
    return ".".join(labels), len(message)


def is_udp53_packet(packet: bytes) -> bool:
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return False
    ihl = (packet[0] & 0x0F) * 4
    if len(packet) < ihl + 8 or packet[9] != 17:
        return False
    src_port, dst_port = struct.unpack('>HH', packet[ihl:ihl + 4])
    return src_port == 53 or dst_port == 53


def parse_ppp_frame(frame: bytes) -> tuple[int, bytes]:
    offset = 0
    if len(frame) >= 2 and frame[0] == 0xFF and frame[1] == 0x03:
        offset = 2
    if offset >= len(frame):
        raise ValueError("Short PPP frame")
    proto = frame[offset]
    offset += 1
    if proto & 1 == 0:
        if offset >= len(frame):
            raise ValueError("Short PPP protocol field")
        proto = (proto << 8) | frame[offset]
        offset += 1
    return proto, frame[offset:]


def build_ppp_frame(proto: int, payload: bytes) -> bytes:
    return b"\xff\x03" + struct.pack(">H", proto) + payload


def option(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value) + 2]) + value


def iter_options(body: bytes):
    for _raw, tag, value in iter_raw_options(body):
        yield tag, value


def iter_raw_options(body: bytes):
    pos = 0
    while pos + 2 <= len(body):
        tag = body[pos]
        length = body[pos + 1]
        if length < 2 or pos + length > len(body):
            return
        raw = body[pos : pos + length]
        yield raw, tag, body[pos + 2 : pos + length]
        pos += length

