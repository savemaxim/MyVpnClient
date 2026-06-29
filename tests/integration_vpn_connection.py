r"""Opt-in real VPN integration harness.

Default mode is safe: it validates the supplied profile and runs preflight only.
It will not connect, open adapters, or change routes unless
--allow-network-changes is explicitly provided.

Example:

    py -B tests\integration_vpn_connection.py --config .\local.integration.json
    py -B tests\integration_vpn_connection.py --config .\local.integration.json --allow-network-changes
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE = REPO_ROOT / "myvpnclient_bridge.py"


def run_bridge(config: Path, command: str, timeout: int = 60) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, "-B", str(BRIDGE), "--config", str(config), command],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    return result.returncode, (result.stdout + result.stderr).strip()


def load_profile(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    required = ["server", "username"]
    missing = [name for name in required if not data.get(name)]
    if missing:
        raise SystemExit(f"Missing required integration config fields: {', '.join(missing)}")
    return data


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Opt-in MyVpnClient real VPN integration harness")
    parser.add_argument("--config", type=Path, required=True, help="Path to an integration config JSON")
    parser.add_argument("--allow-network-changes", action="store_true", help="Actually connect/disconnect and allow adapter/route changes")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(argv)

    config = args.config.resolve()
    load_profile(config)

    code, preflight = run_bridge(config, "preflight-json", timeout=60)
    print("== preflight ==")
    print(preflight)
    if code != 0:
        return code

    if not args.allow_network_changes:
        print("Integration profile is valid. Skipping real connect because --allow-network-changes was not provided.")
        return 0

    print("== connect ==")
    process = subprocess.Popen([sys.executable, "-B", str(BRIDGE), "--config", str(config), "connect"])
    deadline = time.monotonic() + args.timeout_seconds
    try:
        while time.monotonic() < deadline:
            _, status_text = run_bridge(config, "status-json", timeout=20)
            print(status_text)
            try:
                status = json.loads(status_text)
            except json.JSONDecodeError:
                status = {}
            if status.get("connected") or status.get("terminalFailure"):
                break
            time.sleep(5)
    finally:
        print("== disconnect ==")
        _, disconnect = run_bridge(config, "disconnect", timeout=60)
        print(disconnect)
        process.wait(timeout=30)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
