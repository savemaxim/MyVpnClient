import json
import sys
import unittest
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from unittest.mock import patch, MagicMock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from myvpn_tunnel.fortinet import build_tokeninfo_response, looks_like_login_page, parse_tokeninfo
from myvpn_tunnel.ppp import (
    CONFACK,
    CONFNAK,
    CONFREJ,
    CONFREQ,
    FortinetPppEngine,
    IPCP_IPADDR,
    LCP_ACCOMP,
    PPP_IPCP,
    PPP_LCP,
    build_ppp_frame,
    option,
)
from myvpnclient_bridge import (
    classify_myvpn_auth_failure,
    log_connected_session_ended,
    openconnect_interface_alias,
    openconnect_interface_arg_alias,
    parse_openconnect_adapter_alias,
    parse_openconnect_session_expiry,
    required_preflight_paths,
    route_to_prefix,
    route_tracking_interface_alias,
    should_reconnect_after_exit,
    status_payload,
)
from myvpn_tunnel.tap import vpn_peer_gateway


class DummyResult:
    def __init__(self, status, messages):
        self.status = status
        self.messages = messages


class FortinetParserTests(unittest.TestCase):
    def test_tokeninfo_is_detected(self):
        fields = parse_tokeninfo("ret=1,redir=/remote/index,tokeninfo=ftm_push")
        self.assertTrue(fields)

    def test_login_page_is_detected(self):
        self.assertTrue(looks_like_login_page("<form action='/remote/login'><input type='password'></form>"))

    def test_mfa_failure_classification(self):
        result = DummyResult("authentication-required", ["received tokeninfo MFA challenge", "MFA logincheck returned HTTP 200"])
        self.assertIn("MFA approval", classify_myvpn_auth_failure(result))

    def test_ftm_push_response_matches_openconnect_shape(self):
        data = build_tokeninfo_response(
            username="alice",
            realm="vpn",
            token_fields={"tokeninfo": "ftm_push", "reqid": "1", "magic": "remove-me"},
            mfa_code=None,
            blank_mfa=True,
        )
        self.assertEqual(data["username"], "alice")
        self.assertEqual(data["realm"], "vpn")
        self.assertEqual(data["reqid"], "1")
        self.assertEqual(data["code"], "")
        self.assertEqual(data["ftmpush"], "1")
        self.assertNotIn("magic", data)


class RouteHelperTests(unittest.TestCase):
    def test_mask_route_to_prefix(self):
        self.assertEqual(route_to_prefix("10.0.0.0/255.0.0.0"), "10.0.0.0/8")

    def test_tap_route_gateway_matches_openconnect_tunnel_placeholder(self):
        self.assertEqual(vpn_peer_gateway("10.0.125.4"), "10.0.125.4")
        self.assertEqual(vpn_peer_gateway("10.0.125.112"), "10.0.125.112")


class OpenConnectConfigTests(unittest.TestCase):
    def test_openconnect_alias_uses_stable_default_instead_of_legacy_tap_name(self):
        self.assertEqual(openconnect_interface_alias({}), "MyVpnClient")
        self.assertEqual(openconnect_interface_alias({"tapInterfaceAlias": "Local Area Connection"}), "MyVpnClient")

    def test_openconnect_alias_honors_explicit_openconnect_name(self):
        self.assertEqual(openconnect_interface_alias({"openconnectInterfaceAlias": "Test VPN"}), "Test VPN")

    def test_openconnect_alias_falls_back_to_custom_native_alias(self):
        self.assertEqual(openconnect_interface_alias({"tapInterfaceAlias": "Custom VPN"}), "Custom VPN")

    def test_openconnect_default_alias_is_not_forced_as_command_interface(self):
        self.assertEqual(openconnect_interface_arg_alias({}), "")
        self.assertEqual(openconnect_interface_arg_alias({"openconnectInterfaceAlias": "MyVpnClient"}), "")
        self.assertEqual(
            openconnect_interface_arg_alias({"openconnectInterfaceAlias": "MyVpnClient", "openconnectForceInterfaceAlias": True}),
            "MyVpnClient",
        )
        self.assertEqual(openconnect_interface_arg_alias({"openconnectInterfaceAlias": "Test VPN"}), "Test VPN")

    def test_openconnect_routes_track_openconnect_interface(self):
        self.assertEqual(route_tracking_interface_alias({"useOpenconnectBackend": True}), "MyVpnClient")
        self.assertEqual(route_tracking_interface_alias({"useOpenconnectBackend": True, "openconnectInterfaceAlias": "Test VPN"}), "Test VPN")
        self.assertEqual(route_tracking_interface_alias({"useOpenconnectBackend": False, "tapInterfaceAlias": "TAP VPN"}), "TAP VPN")

    def test_openconnect_adapter_alias_is_parsed_from_output(self):
        self.assertEqual(parse_openconnect_adapter_alias("[2026-06-26] 0: Using Wintun device 'MyVpnClient', index 28"), "MyVpnClient")
        self.assertEqual(parse_openconnect_adapter_alias("Could not open Wintun adapter 'MyVpnClient': Element not found."), "")

    def test_openconnect_session_expiry_is_parsed_from_estonian_line(self):
        expiry = parse_openconnect_session_expiry(
            "[2026-06-27 18:57:57] Session authentication will expire at P, 28 juuni 2026 10:57:57 FLE Daylight Time"
        )
        self.assertIsNotNone(expiry)
        self.assertEqual(expiry.strftime("%Y-%m-%d %H:%M:%S"), "2026-06-28 10:57:57")


class PreflightLayoutTests(unittest.TestCase):
    def test_backend_package_is_checked_under_backend_folder(self):
        root = Path("C:/Program Files/MyVpnClient")
        required = dict(required_preflight_paths(root))

        self.assertEqual(required["backend/myvpn_tunnel"], root / "backend" / "myvpn_tunnel")
        self.assertNotIn("myvpn_tunnel", required)


class FakeSocket:
    def send(self, data):
        return len(data)


def control_payload(code, ident, body=b""):
    return struct.pack(">BBH", code, ident, len(body) + 4) + body


def fortinet_frame(proto, payload):
    ppp_frame = build_ppp_frame(proto, payload)
    return struct.pack(">HHH", len(ppp_frame) + 6, 0x5050, len(ppp_frame)) + ppp_frame


class PppFixtureTests(unittest.TestCase):
    def test_lcp_ipcp_phase_progression_from_fixture_frames(self):
        phases = []
        engine = FortinetPppEngine(FakeSocket(), log=lambda _: None, on_phase=lambda phase, detail: phases.append(phase))
        engine.set_phase("lcp-start")
        engine.queue_lcp_request()
        lcp_id = engine.state.lcp_id
        engine.rx_buffer.extend(fortinet_frame(PPP_LCP, control_payload(CONFREQ, 7)))
        engine.rx_buffer.extend(fortinet_frame(PPP_LCP, control_payload(CONFACK, lcp_id)))
        engine.process_rx_buffer()
        engine.tick_negotiation(engine.last_ipcp_request + 3.1)
        ipcp_id = engine.state.ipcp_id
        engine.rx_buffer.extend(
            fortinet_frame(
                PPP_IPCP,
                control_payload(CONFNAK, ipcp_id, option(IPCP_IPADDR, bytes([10, 0, 12, 13]))),
            )
        )
        engine.rx_buffer.extend(fortinet_frame(PPP_IPCP, control_payload(CONFREQ, 8)))
        engine.process_rx_buffer()
        ipcp_id = engine.state.ipcp_id
        engine.rx_buffer.extend(fortinet_frame(PPP_IPCP, control_payload(CONFACK, ipcp_id)))
        engine.process_rx_buffer()
        engine.tick_negotiation(engine.last_ipcp_request + 3.1)
        self.assertIn("lcp-opened", phases)
        self.assertIn("ipcp-start", phases)
        self.assertIn("network-ready", phases)
        self.assertEqual(engine.state.ipv4, "10.0.12.13")

    def test_lcp_accepts_delayed_ack_for_outstanding_request_id(self):
        engine = FortinetPppEngine(FakeSocket(), log=lambda _: None)
        engine.queue_lcp_request()
        lcp_id = engine.state.lcp_id
        engine.rx_buffer.extend(fortinet_frame(PPP_LCP, control_payload(CONFREQ, 7)))
        engine.process_rx_buffer()

        engine.tick_negotiation(engine.last_lcp_request + 3.1)
        self.assertNotEqual(engine.state.lcp_id, lcp_id)
        engine.rx_buffer.extend(fortinet_frame(PPP_LCP, control_payload(CONFACK, lcp_id)))
        engine.process_rx_buffer()

        self.assertTrue(engine.state.lcp_ack_received)
        self.assertEqual(engine.state.phase, "lcp-opened")


    def test_lcp_rejects_unsupported_compression_option(self):
        engine = FortinetPppEngine(FakeSocket(), log=lambda _: None)
        engine.rx_buffer.extend(fortinet_frame(PPP_LCP, control_payload(CONFREQ, 7, option(LCP_ACCOMP, b""))))

        engine.process_rx_buffer()

        proto, payload = engine.outgoing.pop()
        code, ident, length = struct.unpack(">BBH", payload[:4])
        self.assertEqual(proto, PPP_LCP)
        self.assertEqual(code, CONFREJ)
        self.assertEqual(ident, 7)
        self.assertEqual(payload[4:length], option(LCP_ACCOMP, b""))
        self.assertFalse(engine.state.lcp_ack_sent)

    def test_early_ipcp_confreq_is_deferred_until_lcp_open(self):
        engine = FortinetPppEngine(FakeSocket(), log=lambda _: None)
        engine.set_phase("lcp-start")
        engine.queue_lcp_request()
        lcp_id = engine.state.lcp_id

        engine.rx_buffer.extend(fortinet_frame(PPP_IPCP, control_payload(CONFREQ, 8)))
        engine.process_rx_buffer()
        self.assertFalse(engine.state.ipcp_ack_sent)

        engine.rx_buffer.extend(fortinet_frame(PPP_LCP, control_payload(CONFREQ, 7)))
        engine.rx_buffer.extend(fortinet_frame(PPP_LCP, control_payload(CONFACK, lcp_id)))
        engine.process_rx_buffer()

        self.assertTrue(engine.state.ipcp_ack_sent)
        self.assertEqual(engine.state.pending_ipcp_confreq_id, None)

    def test_graceful_terminate_queues_lcp_terminate(self):
        engine = FortinetPppEngine(FakeSocket(), log=lambda _: None, terminate_grace=0)
        engine.graceful_terminate()
        self.assertEqual(engine.state.phase, "terminating")
        self.assertGreater(engine.state.tx_packets, 0)


class StatusPayloadTests(unittest.TestCase):
    def test_legacy_openconnect_backend_is_normalized_to_myvpn(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.json"
            pid_path = root / "openconnect.pid"
            config_path.write_text('{"server":"vpn.example.com","backend":"openconnect"}', encoding="utf-8")
            pid_path.write_text("1234", encoding="utf-8")
            with patch("myvpnclient_bridge.PID_FILE", pid_path), patch("myvpnclient_bridge.is_running", return_value=True):
                payload = status_payload(config_path)
            self.assertEqual(payload["backend"], "myvpn_tunnel")
            self.assertFalse(payload["connected"])
            self.assertEqual(payload["state"], "authenticating")

    def test_connected_at_is_exposed_for_network_ready_state(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.json"
            pid_path = root / "openconnect.pid"
            state_path = root / "myvpn_tunnel.json"
            config_path.write_text('{"server":"vpn.example.com","backend":"myvpn_tunnel"}', encoding="utf-8")
            pid_path.write_text("1234", encoding="utf-8")
            state_path.write_text(
                json.dumps(
                    {
                        "status": "network-ready",
                        "note": "VPN tunnel is up.",
                        "time": "2026-06-26 20:39:59",
                        "connectedAt": "2026-06-26 20:39:58",
                    }
                ),
                encoding="utf-8",
            )

            with (
                patch("myvpnclient_bridge.PID_FILE", pid_path),
                patch("myvpnclient_bridge.MYVPN_STATE_FILE", state_path),
                patch("myvpnclient_bridge.is_running", return_value=True),
            ):
                payload = status_payload(config_path)
            self.assertEqual(payload["connectedAt"], "2026-06-26 20:39:58")

            state_path.write_text(
                json.dumps({"status": "network-ready", "note": "VPN tunnel is up.", "time": "2026-06-26 20:39:59"}),
                encoding="utf-8",
            )
            with (
                patch("myvpnclient_bridge.PID_FILE", pid_path),
                patch("myvpnclient_bridge.MYVPN_STATE_FILE", state_path),
                patch("myvpnclient_bridge.is_running", return_value=True),
            ):
                payload = status_payload(config_path)
            self.assertEqual(payload["connectedAt"], "2026-06-26 20:39:59")

    def test_backend_exit_logs_connected_session_uptime(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "myvpn_tunnel.json"
            log_path = root / "myvpn.log"
            trace_path = root / "trace.jsonl"
            state_path.write_text(
                json.dumps(
                    {
                        "status": "network-ready",
                        "note": "VPN tunnel is up.",
                        "time": "2026-01-01 00:00:00",
                        "connectedAt": "2026-01-01 00:00:00",
                    }
                ),
                encoding="utf-8",
            )

            with (
                patch("myvpnclient_bridge.MYVPN_STATE_FILE", state_path),
                patch("myvpnclient_bridge.ACTIVE_LOG_FILE", log_path),
                patch("myvpnclient_bridge.CURRENT_TRACE_FILE", trace_path),
                patch("myvpnclient_bridge.RUN_TRACE_FILE", None),
            ):
                log_connected_session_ended("openconnect exit")

            self.assertIn(
                "VPN session ended after openconnect exit; connected uptime was ",
                log_path.read_text(encoding="utf-8"),
            )
            self.assertIn('"event": "session_ended"', trace_path.read_text(encoding="utf-8"))

    def test_keepalive_reconnects_only_when_enabled_and_owner_running(self):
        config = {"keepTunnelAliveWhileAppRunning": True}
        with patch("myvpnclient_bridge.owner_is_gone", return_value=False):
            self.assertTrue(should_reconnect_after_exit(config, 1, 0, "network-ready"))
            self.assertFalse(should_reconnect_after_exit(config, 0, 0))
    def test_keepalive_reconnects_after_openconnect_cookie_reject_when_tunnel_was_ready(self):
        config = {"keepTunnelAliveWhileAppRunning": True}
        with patch("myvpnclient_bridge.owner_is_gone", return_value=False):
            self.assertTrue(should_reconnect_after_exit(config, 2, 0, "tunnel-lost"))
            self.assertFalse(should_reconnect_after_exit(config, 2, 0, "tunnel-open-failed"))
            self.assertFalse(should_reconnect_after_exit(config, 2, 0, "authenticated"))


    def test_keepalive_reconnect_limit(self):
        config = {"keepTunnelAliveWhileAppRunning": True, "keepTunnelAliveMaxReconnects": 2}
        with patch("myvpnclient_bridge.owner_is_gone", return_value=False):
            self.assertFalse(should_reconnect_after_exit(config, 1, 2))


if __name__ == "__main__":
    unittest.main()
