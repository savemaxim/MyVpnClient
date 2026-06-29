from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

import myvpnclient_bridge as bridge
from myvpn_tunnel.ppp import (
    CONFREQ,
    FortinetPppEngine,
    PPP_IP,
    PPP_LCP,
    build_ppp_frame,
    iter_options,
    option,
)
from myvpn_tunnel.tunnel import FortinetTlsTunnel
from myvpn_tunnel.tap import route_to_prefix


def fortinet_frame(proto, payload):
    ppp_frame = build_ppp_frame(proto, payload)
    return struct.pack(">HHH", len(ppp_frame) + 6, 0x5050, len(ppp_frame)) + ppp_frame


class FakeSocket:
    def send(self, data):
        return len(data)


class SendAllOnlySocket:
    def __init__(self):
        self.sent = 0

    def send(self, data):
        self.sent += len(data)
        return len(data)


class TunnelLogicalEdgeTests(unittest.TestCase):
    def test_ppp_parser_rejects_http_response_as_tunnel_failure(self):
        engine = FortinetPppEngine(FakeSocket(), log=lambda _: None)
        engine.rx_buffer.extend(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

        with self.assertRaisesRegex(ConnectionError, "Fortinet tunnel request was rejected"):
            engine.process_rx_buffer()

    def test_malformed_option_tail_is_ignored_after_valid_options(self):
        body = option(1, b"\x05\x47") + bytes([5, 10, 1])

        self.assertEqual(list(iter_options(body)), [(1, b"\x05\x47")])

    def test_network_ready_without_tap_does_not_call_on_ready(self):
        ready = []
        phases = []
        engine = FortinetPppEngine(
            FakeSocket(),
            tap=None,
            log=lambda _: None,
            on_ready=lambda ipv4: ready.append(ipv4),
            on_phase=lambda phase, _detail: phases.append(phase),
        )
        engine.state.lcp_ack_sent = True
        engine.state.lcp_ack_received = True
        engine.state.ipcp_ack_sent = True
        engine.state.ipcp_ack_received = True
        engine.state.ipv4 = "10.1.2.3"

        engine.tick_negotiation(engine.last_keepalive + 31)

        self.assertEqual(engine.state.phase, "network-ready")
        self.assertIn("network-ready", phases)
        self.assertEqual(ready, ["10.1.2.3"])

    def test_route_prefix_keeps_invalid_mask_unchanged(self):
        self.assertEqual(route_to_prefix("10.0.0.0/not-a-mask"), "10.0.0.0/not-a-mask")

    def test_ipv4_packet_before_tap_ready_is_dropped_without_exception(self):
        engine = FortinetPppEngine(FakeSocket(), log=lambda _: None)
        engine.rx_buffer.extend(fortinet_frame(PPP_IP, b"E" + b"\x00" * 39))

        engine.process_rx_buffer()

        self.assertEqual(engine.state.rx_packets, 1)

    def test_ppp_engine_send_contract_accepts_send_method(self):
        engine = FortinetPppEngine(SendAllOnlySocket(), log=lambda _: None)
        engine.outgoing.append((PPP_LCP, struct.pack(">BBH", CONFREQ, 1, 4)))

        engine.flush_outgoing()

        self.assertEqual(engine.state.tx_packets, 1)

    def test_tls_open_returns_http_status_when_endpoint_rejects_tunnel(self):
        class FakeSocket:
            response = b"HTTP/1.1 403 Forbidden\r\nX-Test: yes\r\n\r\n"

            def __init__(self):
                self.sent = b""

            def sendall(self, data):
                self.sent += data

            def recv(self, size, flags=0):
                if flags:
                    return self.response[:size]
                chunk = self.response[:size]
                self.response = self.response[size:]
                return chunk

            def close(self):
                return None

        fake_socket = FakeSocket()
        tunnel = FortinetTlsTunnel("https://vpn.example.invalid", "cookie", verify_tls=False, timeout=5)
        with patch("myvpn_tunnel.tunnel.socket.create_connection", return_value=object()), \
             patch("myvpn_tunnel.tunnel.ssl.create_default_context") as context_factory, \
             patch("myvpn_tunnel.tunnel.select.select", return_value=([fake_socket], [], [])):
            context_factory.return_value.wrap_socket.return_value = fake_socket

            result = tunnel.open()

        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.reason, "Forbidden")
        self.assertEqual(result.headers["x-test"], "yes")

    def test_tls_open_returns_http_status_when_http_prefix_is_fragmented(self):
        class FakeSocket:
            chunks = [b"H", b"T", b"T", b"P", b"/", b"1.1 403 Forbidden\r\nX-Test: yes\r\n\r\n"]

            def sendall(self, _data):
                return None

            def recv(self, size):
                if not self.chunks:
                    return b""
                chunk = self.chunks.pop(0)
                if len(chunk) > size:
                    self.chunks.insert(0, chunk[size:])
                    return chunk[:size]
                return chunk

            def close(self):
                return None

        fake_socket = FakeSocket()
        tunnel = FortinetTlsTunnel("https://vpn.example.invalid", "cookie", verify_tls=False, timeout=5)
        with patch("myvpn_tunnel.tunnel.socket.create_connection", return_value=object()), \
             patch("myvpn_tunnel.tunnel.ssl.create_default_context") as context_factory, \
             patch("myvpn_tunnel.tunnel.select.select", return_value=([fake_socket], [], [])):
            context_factory.return_value.wrap_socket.return_value = fake_socket

            result = tunnel.open()

        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.reason, "Forbidden")

    def test_tls_open_preserves_non_http_prefix_for_ppp_stream(self):
        class FakeSocket:
            response = b"\x00\x0aPPPPP" + b"remaining"

            def sendall(self, _data):
                return None

            def recv(self, size):
                chunk = self.response[:size]
                self.response = self.response[size:]
                return chunk

            def send(self, data):
                return len(data)

            def fileno(self):
                return 1

            def setblocking(self, _flag):
                return None

            def close(self):
                return None

        fake_socket = FakeSocket()
        tunnel = FortinetTlsTunnel("https://vpn.example.invalid", "cookie", verify_tls=False, timeout=5)
        with patch("myvpn_tunnel.tunnel.socket.create_connection", return_value=object()), \
             patch("myvpn_tunnel.tunnel.ssl.create_default_context") as context_factory, \
             patch("myvpn_tunnel.tunnel.select.select", return_value=([fake_socket], [], [])):
            context_factory.return_value.wrap_socket.return_value = fake_socket

            result = tunnel.open()

        self.assertEqual(result.status_code, 0)
        self.assertEqual(tunnel.sock.recv(7), b"\x00\x0aPPP")
        self.assertEqual(tunnel.sock.recv(2), b"PP")
        self.assertEqual(tunnel.sock.recv(9), b"remaining")


if __name__ == "__main__":
    unittest.main()
