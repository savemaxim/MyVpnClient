r"""Fast sandbox for MyVpnClient connection orchestration.

This intentionally avoids real VPN credentials, Administrator elevation,
TAP/Wintun adapters, route changes, and Fortinet network calls. It exercises
the bridge-level connection path with fake Fortinet and tunnel components so a
developer can quickly verify state transitions, trace output, and cleanup.

Run from the repository root:

    py -B tests\sandbox_vpn_connection.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

import myvpnclient_bridge as bridge
from myvpn_tunnel.fortinet import VpnConfig


@dataclass
class FakeLoginResult:
    status: str = "authenticated"
    messages: list[str] = field(default_factory=lambda: ["sandbox login accepted"])
    cookie_names: list[str] = field(default_factory=lambda: ["SVPNCOOKIE"])
    cookie_value: str = "sandbox-cookie"
    config: VpnConfig = field(
        default_factory=lambda: VpnConfig(
            platform="sandbox Fortinet",
            dtls_enabled=False,
            assigned_ipv4=["10.44.55.66"],
            dns=["10.44.0.10"],
            routes=["10.44.0.0/255.255.0.0"],
        )
    )

    @property
    def ok(self) -> bool:
        return self.status == "authenticated"


class FakeFortinetClient:
    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def login(self, *_args, **_kwargs) -> FakeLoginResult:
        return FakeLoginResult()


class FakeTap:
    configured: dict | None = None
    closed = False

    def configure(self, ipv4: str, *, routes, dns, metric: int) -> None:
        self.configured = {
            "ipv4": ipv4,
            "routes": list(routes),
            "dns": list(dns),
            "metric": metric,
        }

    def start_reader(self, _queue) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class FakeTlsTunnel:
    def __init__(self, *_args, **_kwargs) -> None:
        self.tap: FakeTap | None = None

    def open(self):
        return type("OpenResult", (), {"status_code": 0, "reason": "sandbox tunnel opened"})()

    def run(
        self,
        *,
        should_stop,
        log,
        tap=None,
        routes=None,
        dns=None,
        metric=1,
        on_ready=None,
        on_phase=None,
        on_stats=None,
        **_kwargs,
    ) -> int:
        self.tap = tap
        log("sandbox tunnel run started")
        if on_phase:
            on_phase("lcp-start", "Sandbox LCP started.")
            on_phase("lcp-opened", "Sandbox LCP opened.")
            on_phase("ipcp-start", "Sandbox IPCP started.")
        if tap:
            tap.configure(
                "10.44.55.66",
                routes=routes or [],
                dns=dns or [],
                metric=metric,
            )
            tap.start_reader(None)
        if on_ready:
            on_ready("10.44.55.66")
        if on_stats:
            on_stats(
                {
                    "phase": "network-ready",
                    "rxPackets": 2,
                    "txPackets": 3,
                    "lastRxSecondsAgo": 0,
                    "lastTxSecondsAgo": 0,
                }
            )
        return 0 if not should_stop() else 1

    def close(self) -> None:
        return None


def run_sandbox() -> int:
    with tempfile.TemporaryDirectory(prefix="myvpnclient-sandbox-") as temp_dir:
        state_dir = Path(temp_dir)
        config = {
            "server": "sandbox.invalid",
            "username": "sandbox-user",
            "password": "sandbox-password",
            "authgroup": "",
            "autoPushMfa": True,
            "mfaBlankResponses": 1,
            "preferDtls": False,
            "pppNegotiationTimeoutSeconds": 3,
            "tunnelIdleTimeoutSeconds": 0,
            "terminateGraceSeconds": 0,
            "tapInterfaceAlias": "Sandbox TAP",
            "tapInterfaceMetric": 7,
        }

        patches = [
            patch.object(bridge, "STATE_DIR", state_dir),
            patch.object(bridge, "PID_FILE", state_dir / "openconnect.pid"),
            patch.object(bridge, "OWNER_PID_FILE", state_dir / "myvpnclient-owner.pid"),
            patch.object(bridge, "MYVPN_STATE_FILE", state_dir / "myvpn_tunnel.json"),
            patch.object(bridge, "LOG_FILE", state_dir / "myvpn.log"),
            patch.object(bridge, "LEGACY_LOG_FILE", state_dir / "openconnect.log"),
            patch.object(bridge, "TRACE_DIR", state_dir / "traces"),
            patch.object(bridge, "CURRENT_TRACE_FILE", state_dir / "myvpn_tunnel-current-trace.jsonl"),
            patch.object(bridge, "MYVPN_ROUTES_FILE", state_dir / "myvpn_tunnel-routes.json"),
            patch.object(bridge, "NETWORK_TRANSACTION_FILE", state_dir / "myvpn_tunnel-network-transaction.json"),
            patch.object(bridge, "require_admin_for_windows", lambda: None),
            patch.object(bridge, "cleanup_windows_network_state", lambda *_args, **_kwargs: None),
            patch.object(bridge, "capture_network_transaction", lambda *_args, **_kwargs: None),
            patch.object(bridge, "FortinetClient", FakeFortinetClient),
            patch.object(bridge, "FortinetTlsTunnel", FakeTlsTunnel),
            patch.object(bridge, "open_myvpn_packet_adapter", lambda _config: FakeTap()),
        ]

        with patches[0]:
            for active_patch in patches[1:]:
                active_patch.start()
            try:
                exit_code = bridge.connect_myvpn_once(config)
                routes = json.loads((state_dir / "myvpn_tunnel-routes.json").read_text(encoding="utf-8"))
                trace_records = [
                    json.loads(line)
                    for line in (state_dir / "myvpn_tunnel-current-trace.jsonl").read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                trace_events = [record["event"] for record in trace_records]
                state_records = [record for record in trace_records if record["event"] == "state"]
                print("sandbox exit:", exit_code)
                print("sandbox final state file:", "present" if (state_dir / "myvpn_tunnel.json").exists() else "cleaned")
                print("sandbox state transitions:", json.dumps(state_records, indent=2))
                print("sandbox routes:", json.dumps(routes, indent=2))
                print("sandbox trace events:", ", ".join(trace_events))

                assert exit_code == 0
                assert any(record.get("status") == "network-ready" and record.get("ipv4") == "10.44.55.66" for record in state_records)
                assert "10.44.0.0/16" in routes["routes"]
                assert "connect_start" in trace_events
                assert "tls_tunnel_opened" in trace_events
                assert "network_routes_tracked" in trace_events
            finally:
                for active_patch in reversed(patches[1:]):
                    active_patch.stop()

    print("sandbox result: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_sandbox())
