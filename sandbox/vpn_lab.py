from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time


LAB_DIR = Path(__file__).resolve().parent
ROOT = LAB_DIR.parent
RUNS_DIR = LAB_DIR / "runs"
PROGRAMDATA = Path(r"C:\ProgramData\MyVpnClient")
PROGRAMDATA_STATE = PROGRAMDATA / "state"
DEFAULT_CONFIG = PROGRAMDATA / "config.json"
DEFAULT_OPENCONNECT_SOURCE = ROOT.parent / "openconnect"
DEFAULT_VPN_HOSTS: list[str] = []
SENSITIVE = re.compile(r"(?i)(password|passwd|credential|cookie|svpncookie|token|secret|key)\s*[:=]\s*([^\r\n,; ]+)")


def now_stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def redact(text: str) -> str:
    return SENSITIVE.sub(lambda m: f"{m.group(1)}=<redacted>", text or "")


def run_dir(name: str) -> Path:
    path = RUNS_DIR / f"{now_stamp()}-{name}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact(text), encoding="utf-8", errors="replace")


def command_text(cmd: list[str]) -> str:
    return " ".join(f'"{part}"' if " " in part else part for part in cmd)


def run_capture(cmd: list[str], *, timeout: int = 20, input_text: str | None = None) -> tuple[int, str]:
    try:
        result = subprocess.run(
            cmd,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return result.returncode, redact((result.stdout or "") + (result.stderr or ""))
    except subprocess.TimeoutExpired as exc:
        return 124, redact((exc.stdout or "") + (exc.stderr or "") + f"\nTIMEOUT after {timeout}s: {command_text(cmd)}")


def ps(script: str, *, timeout: int = 20) -> tuple[int, str]:
    return run_capture(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=timeout)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_bridge(lab_state: Path):
    bridge_path = ROOT / "myvpnclient_bridge.py"
    spec = importlib.util.spec_from_file_location("myvpnclient_bridge_lab", bridge_path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to import {bridge_path}")
    bridge = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT))
    spec.loader.exec_module(bridge)

    lab_state.mkdir(parents=True, exist_ok=True)
    bridge.STATE_DIR = lab_state
    bridge.PID_FILE = lab_state / "openconnect.pid"
    bridge.OWNER_PID_FILE = lab_state / "myvpnclient-owner.pid"
    bridge.MYVPN_STATE_FILE = lab_state / "myvpn_tunnel.json"
    bridge.LOG_FILE = lab_state / "myvpn.log"
    bridge.LEGACY_LOG_FILE = lab_state / "openconnect.log"
    bridge.TRACE_DIR = lab_state / "traces"
    bridge.DIAGNOSTICS_DIR = lab_state / "diagnostics"
    bridge.CURRENT_TRACE_FILE = lab_state / "myvpn_tunnel-current-trace.jsonl"
    bridge.RUN_TRACE_FILE = None
    bridge.MYVPN_ROUTES_FILE = lab_state / "myvpn_tunnel-routes.json"
    bridge.NETWORK_TRANSACTION_FILE = lab_state / "myvpn_tunnel-network-transaction.json"

    password_blob = PROGRAMDATA_STATE / "password.dpapi"
    def lab_password() -> str:
        return bridge.dpapi_unprotect(password_blob.read_bytes()).decode("utf-8")
    bridge.load_dpapi_password = lab_password
    return bridge


def collect_snapshot(out: Path, config_path: Path) -> None:
    config = load_json(config_path)
    hosts = config.get("connectivityCheckHosts") or DEFAULT_VPN_HOSTS
    if isinstance(hosts, str):
        hosts = [x.strip() for x in hosts.split(",") if x.strip()]
    dns_servers = config.get("vpnDnsServers") or []

    commands = {
        "adapters.json": "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Select Name,InterfaceDescription,InterfaceIndex,Status,MacAddress,LinkSpeed | Sort InterfaceIndex | ConvertTo-Json -Depth 5",
        "ip-local-area-connection.json": "Get-NetIPAddress -InterfaceAlias 'Local Area Connection' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState,SkipAsSource,PolicyStore | ConvertTo-Json -Depth 5",
        "dns-client.json": "Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select InterfaceAlias,InterfaceIndex,ServerAddresses | ConvertTo-Json -Depth 5",
        "routes-10.json": "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -like '10.*' -or $_.DestinationPrefix -eq '0.0.0.0/0' } | Sort DestinationPrefix,InterfaceMetric,RouteMetric | Select DestinationPrefix,NextHop,InterfaceAlias,InterfaceIndex,RouteMetric,InterfaceMetric,PolicyStore | ConvertTo-Json -Depth 5",
    }
    for name, script in commands.items():
        code, output = ps(script, timeout=15)
        write_text(out / name, f"exit={code}\n{output}\n")

    for host in hosts:
        code, output = ps(f"Resolve-DnsName '{host}' -Type A -ErrorAction SilentlyContinue | Select Name,Type,IPAddress,NameHost | ConvertTo-Json -Depth 4", timeout=10)
        write_text(out / f"dns-default-{safe_name(host)}.txt", f"exit={code}\n{output}\n")
        for server in dns_servers:
            code, output = ps(f"Resolve-DnsName '{host}' -Server '{server}' -Type A -ErrorAction SilentlyContinue | Select Name,Type,IPAddress,NameHost | ConvertTo-Json -Depth 4", timeout=6)
            write_text(out / f"dns-{safe_name(host)}-at-{safe_name(server)}.txt", f"exit={code}\n{output}\n")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def preflight(args) -> int:
    out = run_dir("preflight")
    lines = []
    lines.append(f"root={ROOT}")
    lines.append(f"config={args.config}")
    lines.append(f"openconnect_source={args.openconnect_source}")
    for cmd in [
        ["openconnect", "--version"],
        [sys.executable, "--version"],
        ["dotnet", "--version"],
    ]:
        code, output = run_capture(cmd, timeout=10)
        lines.append(f"\n$ {command_text(cmd)}\nexit={code}\n{output.strip()}")
    write_text(out / "preflight.txt", "\n".join(lines) + "\n")
    collect_snapshot(out / "snapshot", Path(args.config))
    print_live(str(out))
    return 0


def collect(args) -> int:
    out = run_dir("collect")
    collect_snapshot(out, Path(args.config))
    print_live(str(out))
    return 0


def compare_sources(args) -> int:
    out = run_dir("compare-sources")
    oc = Path(args.openconnect_source)
    snippets = {
        "openconnect-fortinet-config.txt": (oc / "fortinet.c", [(344, 390), (613, 767), (775, 820)]),
        "openconnect-tap-win32.txt": (oc / "tun-win32.c", [(636, 709)]),
        "openconnect-ppp-ipcp.txt": (oc / "ppp.c", [(211, 247), (379, 541), (543, 620), (637, 735), (880, 965), (1459, 1486)]),
        "openconnect-vpnc-script-win.txt": (Path(r"C:\Program Files\OpenConnect\vpnc-script-win.js"), [(145, 242)]),
        "myvpn-tap.txt": (ROOT / "backend" / "myvpn_tunnel" / "tap.py", [(60, 90), (197, 276)]),
        "myvpn-ppp.txt": (ROOT / "backend" / "myvpn_tunnel" / "ppp.py", [(190, 245), (246, 335), (336, 430)]),
    }
    for name, (path, ranges) in snippets.items():
        text = []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        text.append(f"### {path}")
        for start, end in ranges:
            text.append(f"--- lines {start}-{end} ---")
            for i in range(start - 1, min(end, len(lines))):
                text.append(f"{i + 1}: {lines[i]}")
        write_text(out / name, "\n".join(text) + "\n")
    print_live(str(out))
    return 0



def incremental_probe(out: Path, config_path: Path, *, label: str = "probe") -> dict:
    config = load_json(config_path)
    dns_servers = config.get("vpnDnsServers") or []
    if isinstance(dns_servers, str):
        dns_servers = [item.strip() for item in dns_servers.split(",") if item.strip()]
    jira_host = str(config.get("probeHost") or config.get("jiraCheckHost") or "")
    dns_host = str(config.get("dnsCheckHost") or "")
    report: dict = {"label": label, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "steps": []}

    def step(name: str, script: str, timeout: int = 15, ok_contains: list[str] | None = None) -> None:
        code, output = ps(script, timeout=timeout)
        ok = code == 0 and all(token in output for token in (ok_contains or []))
        item = {"name": name, "exit": code, "ok": ok, "output": output[-5000:]}
        report["steps"].append(item)
        write_text(out / f"{safe_name(label)}-{safe_name(name)}.txt", f"exit={code}\nok={ok}\n{output}\n")

    step(
        "adapter-ip",
        "Get-NetIPAddress -InterfaceAlias 'Local Area Connection' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength | ConvertTo-Json -Depth 4",
        ok_contains=[],
    )
    for server in dns_servers:
        step(
            f"route-dns-{server}",
            f"Find-NetRoute -RemoteIPAddress '{server}' -ErrorAction SilentlyContinue | Select DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric | ConvertTo-Json -Depth 4",
            ok_contains=["Local Area Connection"],
        )
        step(
            f"dns-{server}-{dns_host}",
            f"Resolve-DnsName '{dns_host}' -Server '{server}' -Type A -DnsOnly -ErrorAction SilentlyContinue | Select Name,Type,IPAddress | ConvertTo-Json -Depth 4",
            timeout=8,
            ok_contains=["10."],
        )
    step(
        f"dns-default-{jira_host}",
        f"Resolve-DnsName '{jira_host}' -Type A -ErrorAction SilentlyContinue | Select Name,Type,IPAddress | ConvertTo-Json -Depth 4",
        timeout=8,
        ok_contains=["IPAddress"],
    )
    step(
        f"route-jira-{jira_host}",
        f"$ip=(Resolve-DnsName '{jira_host}' -Type A -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress); if (-not $ip) {{ throw 'No A record for {jira_host}' }}; Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Select DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric | ConvertTo-Json -Depth 4",
        ok_contains=["Local Area Connection"],
    )
    step(
        f"tcp-jira-{jira_host}",
        f"$ip=(Resolve-DnsName '{jira_host}' -Type A -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress); if (-not $ip) {{ throw 'No A record for {jira_host}' }}; $started=Get-Date; $c=New-Object Net.Sockets.TcpClient; $iar=$c.BeginConnect($ip,443,$null,$null); $ok=$iar.AsyncWaitHandle.WaitOne(15000,$false); if ($ok) {{ try {{ $c.EndConnect($iar); $connected=$true }} catch {{ $connected=$false; $err=$_.Exception.Message }} }} else {{ $connected=$false; $err='timeout' }}; $elapsed=[math]::Round(((Get-Date)-$started).TotalSeconds,3); $c.Close(); [pscustomobject]@{{Host='{jira_host}';Address=$ip;Connected=$connected;ElapsedSeconds=$elapsed;Error=$err}}|ConvertTo-Json -Depth 3",
        timeout=25,
        ok_contains=["true"],
    )
    step(
        f"https-jira-{jira_host}",
        f"$started=Get-Date; $outFile=Join-Path $env:TEMP 'myvpn-sandbox-jira.html'; Remove-Item -LiteralPath $outFile -ErrorAction SilentlyContinue; curl.exe -k -L --fail-with-body --connect-timeout 20 --max-time 90 -sS -w '\nCURL_HTTP_CODE=%{{http_code}}\nCURL_TIME_CONNECT=%{{time_connect}}\nCURL_TIME_APPCONNECT=%{{time_appconnect}}\nCURL_TIME_TOTAL=%{{time_total}}\n' -D - https://{jira_host}/ -o $outFile; $code=$LASTEXITCODE; $plain=''; if (Test-Path $outFile) {{ $body=Get-Content $outFile -Raw -ErrorAction SilentlyContinue; $plain=($body -replace '<script[\\s\\S]*?</script>',' ' -replace '<style[\\s\\S]*?</style>',' ' -replace '<[^>]+>',' ' -replace '\\s+',' ').Trim(); if ($plain.Length -gt 500) {{ $plain=$plain.Substring(0,500) }} }}; $elapsed=[math]::Round(((Get-Date)-$started).TotalSeconds,3); [pscustomobject]@{{CurlExit=$code;ElapsedSeconds=$elapsed;Preview=$plain}}|ConvertTo-Json -Depth 4; exit $code",
        timeout=120,
        ok_contains=["CurlExit"],
    )
    report["ok"] = all(step["ok"] for step in report["steps"])
    write_text(out / f"{safe_name(label)}-incremental-report.json", json.dumps(report, indent=2))
    return report


def read_json_safe(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"_error": repr(exc), "_path": str(path)}


def local_time_epoch(value: object) -> float | None:
    if not value:
        return None
    try:
        return time.mktime(time.strptime(str(value), "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return None


def pid_running(pid: int | None) -> bool:
    if not pid:
        return False
    code, output = run_capture(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], timeout=8)
    return code == 0 and (f'"{pid}"' in output or f",{pid}," in output)


def read_pid_file(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return None



def print_live(message: str) -> None:
    print(redact(message), flush=True)


def summarize_live_trace_event(event: dict) -> str | None:
    name = event.get("event")
    when = event.get("time", "")
    prefix = f"{when} " if when else ""
    if name == "connect_start":
        return prefix + f"MyVpn connect_start version={event.get('version')} python={event.get('python')}"
    if name == "login_start":
        return prefix + f"Auth login_start attempt={event.get('attempt')} blank_mfa={event.get('blank_mfa')}"
    if name == "login_http":
        return prefix + (
            "Auth HTTP "
            f"{event.get('method')} {event.get('path')} -> {event.get('status')} "
            f"request={event.get('request', 'probe')} response={event.get('response')} cookies={event.get('cookies')}"
        )
    if name == "login_note":
        return prefix + f"Auth note: {event.get('message')}"
    if name == "login_result":
        return prefix + f"Auth result: {event.get('status')} cookies={event.get('cookies')}"
    if name == "state":
        bits = [str(event.get("status") or "state")]
        if event.get("mfaStatus"):
            bits.append(f"mfa={event.get('mfaStatus')}")
        if event.get("note"):
            bits.append(str(event.get("note")))
        return prefix + "State " + " | ".join(bits)
    if name in {"dtls_open_start", "tls_tunnel_open_start", "tls_tunnel_opened", "network_routes_tracked", "network_check_start", "network_check_retry", "tunnel_exit", "persistent_connect_exit"}:
        compact = {k: v for k, v in event.items() if k not in {"_traceFile", "time"}}
        return prefix + json.dumps(compact, ensure_ascii=False)
    if name == "ppp_phase":
        return prefix + f"PPP {event.get('phase')}: {event.get('detail')}"
    if name == "ppp_stats":
        return prefix + f"PPP stats phase={event.get('phase')} rx={event.get('rxPackets')} tx={event.get('txPackets')} lastRx={event.get('lastRxSecondsAgo')}s"
    if name and (name.startswith("network_check") or name.startswith("dns_")):
        compact = {k: v for k, v in event.items() if k not in {"_traceFile", "time"}}
        return prefix + json.dumps(compact, ensure_ascii=False)
    return None


def live_tail_mypvn_state(state_dir: Path, stop: threading.Event) -> None:
    seen_events: set[tuple[str, int]] = set()
    log_offsets: dict[Path, int] = {}
    last_any = 0.0
    while not stop.is_set():
        try:
            for log_file in (state_dir / "myvpn.log", state_dir / "openconnect.log"):
                if log_file.exists():
                    pos = log_offsets.get(log_file, 0)
                    with log_file.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(pos)
                        for raw in fh:
                            line = raw.rstrip()
                            if line:
                                label = "MyVpn log" if log_file.name.lower() == "myvpn.log" else "MyVpn legacy log"
                                print_live(label + ": " + line)
                                last_any = time.time()
                        log_offsets[log_file] = fh.tell()
            for event in latest_trace_events(state_dir, since=0, limit=2000):
                trace_file = event.get("_traceFile", "")
                key = (trace_file, hash(json.dumps(event, sort_keys=True, ensure_ascii=False)))
                if key in seen_events:
                    continue
                seen_events.add(key)
                summary = summarize_live_trace_event(event)
                if summary:
                    print_live("MyVpn trace: " + summary)
                    last_any = time.time()
            if time.time() - last_any > 15:
                print_live("MyVpn live: waiting for auth/tunnel trace output...")
                last_any = time.time()
        except Exception as exc:
            print_live(f"MyVpn live tail error: {exc}")
        stop.wait(1.0)



def latest_trace_events(state_dir: Path, *, since: float = 0.0, limit: int = 1200) -> list[dict]:
    files: list[Path] = []
    current = state_dir / "myvpn_tunnel-current-trace.jsonl"
    if current.exists() and current.stat().st_mtime >= since - 2:
        files.append(current)
    traces = state_dir / "traces"
    if traces.exists():
        files.extend(
            sorted(
                [item for item in traces.glob("myvpn_tunnel-run-*.jsonl") if item.stat().st_mtime >= since - 2],
                key=lambda item: item.stat().st_mtime,
            )
        )
    events: list[dict] = []
    for trace_file in files[-4:]:
        try:
            for line in trace_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event["_traceFile"] = str(trace_file)
                events.append(event)
        except OSError:
            continue
    return events[-limit:]


def extract_ips_from_text(value: object) -> list[str]:
    text_value = json.dumps(value) if isinstance(value, (dict, list)) else str(value or "")
    return re.findall(r"\b(?:10|172|192|195)\.(?:\d{1,3}\.){2}\d{1,3}\b", text_value)


def trace_ips_for_host(state_dir: Path, host: str, *, since: float) -> list[str]:
    ips: list[str] = []
    host_l = host.lower().rstrip(".")
    for event in latest_trace_events(state_dir, since=since):
        blob = json.dumps(event, ensure_ascii=False).lower()
        if host_l not in blob:
            continue
        for key in ("answers", "answerA", "requested", "output", "note", "detail"):
            if key in event:
                for ip in extract_ips_from_text(event.get(key)):
                    if ip not in ips:
                        ips.append(ip)
    return ips


def bridge_version(path: Path) -> str:
    if not path.exists():
        return "missing"
    try:
        match = re.search(r'MYVPNCLIENT_VERSION\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8", errors="replace"))
        return match.group(1) if match else "unknown"
    except OSError:
        return "unreadable"


def app_installed_paths() -> dict:
    install_dir = Path(r"C:\Program Files\MyVpnClient")
    return {
        "installDir": str(install_dir),
        "launcher": str(install_dir / "MyVpnTunnel.exe"),
        "bridge": str(install_dir / "myvpnclient_bridge.py"),
        "sourceBridge": str(ROOT / "myvpnclient_bridge.py"),
    }


def run_ps_step(out: Path, report: dict, name: str, script: str, *, timeout: int = 20, ok_tokens: list[str] | None = None) -> str:
    code, output = ps(script, timeout=timeout)
    ok = code == 0 and all(token in output for token in (ok_tokens or []))
    item = {"name": name, "exit": code, "ok": ok, "output": output[-7000:]}
    report.setdefault("steps", []).append(item)
    write_text(out / f"{safe_name(name)}.txt", f"exit={code}\nok={ok}\n{output}\n")
    return output


def jira_vpn_probe(out: Path, config_path: Path, *, since: float, label: str) -> dict:
    config = load_json(config_path)
    jira_host = str(config.get("probeHost") or config.get("jiraCheckHost") or "")
    dns_servers = config.get("vpnDnsServers") or []
    if isinstance(dns_servers, str):
        dns_servers = [item.strip() for item in dns_servers.split(",") if item.strip()]
    report: dict = {
        "label": label,
        "host": jira_host,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "steps": [],
        "candidateIps": [],
    }

    default_output = run_ps_step(
        out,
        report,
        f"default-dns-{jira_host}",
        f"Resolve-DnsName '{jira_host}' -Type A -ErrorAction SilentlyContinue | Select Name,IPAddress | ConvertTo-Json -Depth 4",
        timeout=12,
    )
    candidate_ips: list[str] = []
    for ip in extract_ips_from_text(default_output):
        if ip not in candidate_ips:
            candidate_ips.append(ip)

    for dns in dns_servers:
        output = run_ps_step(
            out,
            report,
            f"vpn-dns-{dns}-{jira_host}",
            f"Resolve-DnsName '{jira_host}' -Type A -Server '{dns}' -DnsOnly -ErrorAction SilentlyContinue | Select Name,IPAddress | ConvertTo-Json -Depth 4",
            timeout=8,
        )
        for ip in extract_ips_from_text(output):
            if ip not in candidate_ips:
                candidate_ips.append(ip)

    for ip in trace_ips_for_host(PROGRAMDATA_STATE, jira_host, since=since):
        if ip not in candidate_ips:
            candidate_ips.append(ip)

    configured_known = config.get("knownJiraIps") or config.get("jiraKnownIps") or []
    if isinstance(configured_known, str):
        configured_known = [item.strip() for item in configured_known.split(",") if item.strip()]
    priority_ips: list[str] = []
    for ip in configured_known:
        ip_text = str(ip).strip()
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip_text):
            if ip_text not in priority_ips:
                priority_ips.append(ip_text)
            if ip_text not in candidate_ips:
                candidate_ips.append(ip_text)

    dns_server_set = {str(item).strip() for item in dns_servers}
    candidate_ips = [ip for ip in candidate_ips if ip not in dns_server_set or ip in priority_ips]
    # Keep the public/default candidates for contrast, but test configured private Jira first.
    candidate_ips = sorted(candidate_ips, key=lambda ip: (0 if ip in priority_ips else 1 if ip.startswith("10.") else 2, ip))
    report["candidateIps"] = candidate_ips

    for ip in candidate_ips:
        route_output = run_ps_step(
            out,
            report,
            f"route-{jira_host}-{ip}",
            f"Find-NetRoute -RemoteIPAddress '{ip}' -ErrorAction SilentlyContinue | Select DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,InterfaceMetric | ConvertTo-Json -Depth 4",
            timeout=12,
        )
        tcp_output = run_ps_step(
            out,
            report,
            f"tcp-{jira_host}-{ip}",
            "$started=Get-Date; "
            f"$ip='{ip}'; "
            "$c=New-Object Net.Sockets.TcpClient; "
            "$iar=$c.BeginConnect($ip,443,$null,$null); "
            "$ok=$iar.AsyncWaitHandle.WaitOne(10000,$false); "
            "if ($ok) { try { $c.EndConnect($iar); $connected=$true } catch { $connected=$false; $err=$_.Exception.Message } } "
            "else { $connected=$false; $err='timeout' }; "
            "$elapsed=[math]::Round(((Get-Date)-$started).TotalSeconds,3); $c.Close(); "
            f"[pscustomobject]@{{Host='{jira_host}';Address=$ip;Connected=$connected;ElapsedSeconds=$elapsed;Error=$err}}|ConvertTo-Json -Depth 4; "
            "if (-not $connected) { exit 2 }",
            timeout=18,
            ok_tokens=["true"],
        )
        https_output = run_ps_step(
            out,
            report,
            f"https-{jira_host}-{ip}",
            "$started=Get-Date; "
            "$outFile=Join-Path $env:TEMP ('myvpn-jira-' + [guid]::NewGuid().ToString() + '.html'); "
            f"curl.exe -k -L --resolve {jira_host}:443:{ip} --connect-timeout 10 --max-time 45 -sS "
            "-w \"`nCURL_HTTP_CODE=%{http_code}`nCURL_TIME_CONNECT=%{time_connect}`nCURL_TIME_APPCONNECT=%{time_appconnect}`nCURL_TIME_TOTAL=%{time_total}`n\" "
            f"https://{jira_host}/ -o $outFile; "
            "$curlExit=$LASTEXITCODE; $body=''; "
            "if (Test-Path $outFile) { $raw=Get-Content $outFile -Raw -ErrorAction SilentlyContinue; "
            "$body=($raw -replace '<script[\\s\\S]*?</script>',' ' -replace '<style[\\s\\S]*?</style>',' ' -replace '<[^>]+>',' ' -replace '\\s+',' ').Trim(); "
            "if ($body.Length -gt 800) { $body=$body.Substring(0,800) }; Remove-Item -LiteralPath $outFile -ErrorAction SilentlyContinue }; "
            "$elapsed=[math]::Round(((Get-Date)-$started).TotalSeconds,3); "
            "[pscustomobject]@{CurlExit=$curlExit;ElapsedSeconds=$elapsed;Preview=$body}|ConvertTo-Json -Depth 4; "
            "exit $curlExit",
            timeout=70,
        )
        private_route = ip.startswith("10.") and "Local Area Connection" in route_output
        https_ok = "CURL_HTTP_CODE=200" in https_output or "CURL_HTTP_CODE=302" in https_output or "CURL_HTTP_CODE=301" in https_output
        page_not_found = "Page not found" in https_output or "This site can't be reached" in https_output
        report.setdefault("classifications", []).append(
            {
                "ip": ip,
                "privateVpnIp": ip.startswith("10."),
                "routeUsesTap": "Local Area Connection" in route_output,
                "tcpConnected": '"Connected":  true' in tcp_output or '"Connected":true' in tcp_output or "Connected\": true" in tcp_output,
                "httpsOk": https_ok,
                "pageNotFoundLike": page_not_found,
                "vpnProof": private_route and https_ok and not page_not_found,
            }
        )

    report["ok"] = any(item.get("vpnProof") for item in report.get("classifications", []))
    write_text(out / f"{safe_name(label)}-jira-vpn-probe.json", json.dumps(report, indent=2))
    return report


def launch_installed_app_like(out: Path, started: float) -> dict:
    launcher = Path(r"C:\Program Files\MyVpnClient\MyVpnTunnel.exe")
    if not launcher.exists():
        return {"ok": False, "method": "installed", "error": f"Missing {launcher}"}
    query, query_output = run_capture(["schtasks.exe", "/Query", "/TN", "MyVpnClient-Connect", "/FO", "LIST", "/V"], timeout=10)
    if query == 0 and str(launcher).lower() in query_output.lower():
        code, output = run_capture(["schtasks.exe", "/Run", "/TN", "MyVpnClient-Connect"], timeout=10)
        write_text(out / "connect-launch.txt", f"method=schtasks\nexit={code}\n{output}\n")
        return {"ok": code == 0, "method": "schtasks", "exit": code, "output": output[-2000:]}
    launcher_ps = str(launcher).replace("'", "''")
    programdata_ps = str(PROGRAMDATA).replace("'", "''")
    script = (
        f"Start-Process -FilePath '{launcher_ps}' "
        "-ArgumentList 'connect-watch' "
        f"-WorkingDirectory '{programdata_ps}' "
        "-WindowStyle Hidden -Verb RunAs"
    )
    code, output = ps(script, timeout=20)
    write_text(out / "connect-launch.txt", f"method=Start-Process-RunAs\nexit={code}\n{output}\n")
    return {"ok": code == 0, "method": "Start-Process-RunAs", "exit": code, "output": output[-2000:]}


def launch_source_app_like(out: Path, config_path: Path, *, bypass_network_check: bool = False) -> tuple[subprocess.Popen | None, dict]:
    bridge = ROOT / "myvpnclient_bridge.py"
    task_name = "MyVpnClient-SourceConnect"
    log_path = out / "source-scheduled.log"
    cmd_path = out / "source-connect.cmd"
    if bypass_network_check:
        wrapper_path = out / "source-connect-live-wrapper.py"
        wrapper_path.write_text(
            "import os, sys\n"
            "from pathlib import Path\n"
            f"os.environ['MYVPNCLIENT_DATA_DIR'] = r'{PROGRAMDATA}'\n"
            f"sys.path.insert(0, r'{ROOT}')\n"
            "import myvpnclient_bridge as bridge\n"
            "def bypass_network_check(config, vpn_config, ipv4=''):\n"
            "    bridge.trace_event('sandbox_network_check_bypassed', ipv4=ipv4, reason='source-app-live')\n"
            "    return True, 'sandbox bypass: scheduled tunnel held open for external Jira probes'\n"
            "bridge.verify_myvpn_network_ready = bypass_network_check\n"
            "config = bridge.load_config(Path(sys.argv[1]))\n"
            "config['keepTunnelAliveWhileAppRunning'] = True\n"
            "config['diagnosticStopAfterNetworkCheck'] = False\n"
            "raise SystemExit(bridge.connect_myvpn(config))\n",
            encoding="utf-8",
        )
        connect_line = f"\"{sys.executable}\" -B \"{wrapper_path}\" \"{config_path}\" >> \"{log_path}\" 2>>&1"
    else:
        connect_line = f"\"{sys.executable}\" -B \"{bridge}\" --config \"{config_path}\" connect-watch >> \"{log_path}\" 2>>&1"
    cmd_path.write_text(
        "@echo off\r\n"
        f"set MYVPNCLIENT_DATA_DIR={PROGRAMDATA}\r\n"
        "set PYTHONWARNINGS=ignore::SyntaxWarning\r\n"
        f"cd /d {PROGRAMDATA}\r\n"
        f"{connect_line}\r\n",
        encoding="utf-8",
    )
    task_cmd = f'cmd.exe /c ""{cmd_path}""'
    run_capture(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], timeout=10)
    create_cmd = [
        "schtasks.exe",
        "/Create",
        "/TN",
        task_name,
        "/SC",
        "ONCE",
        "/ST",
        "23:59",
        "/RL",
        "HIGHEST",
        "/TR",
        task_cmd,
        "/F",
    ]
    create_code, create_output = run_capture(create_cmd, timeout=15)
    if create_code != 0:
        write_text(out / "connect-launch.txt", f"method=source-scheduled\ncreate exit={create_code}\n{create_output}\n")
        return None, {"ok": False, "method": "source-scheduled", "exit": create_code, "output": create_output[-2000:]}
    run_code, run_output = run_capture(["schtasks.exe", "/Run", "/TN", task_name], timeout=10)
    write_text(out / "connect-launch.txt", f"method=source-scheduled\ncreate exit={create_code}\n{create_output}\nrun exit={run_code}\n{run_output}\ncmd={cmd_path}\n")
    return None, {"ok": run_code == 0, "method": "source-scheduled", "exit": run_code, "output": (create_output + run_output)[-2000:], "bridge": str(bridge), "task": task_name}


def stop_app_like(out: Path, config_path: Path, proc: subprocess.Popen | None = None) -> None:
    code, output = run_capture(["schtasks.exe", "/Run", "/TN", "MyVpnClient-Disconnect"], timeout=10)
    write_text(out / "disconnect-launch.txt", f"method=schtasks\nexit={code}\n{output}\n")
    if code != 0:
        env = os.environ.copy()
        env["MYVPNCLIENT_DATA_DIR"] = str(PROGRAMDATA)
        bridge = ROOT / "myvpnclient_bridge.py"
        code2, output2 = run_capture_env([sys.executable, "-B", str(bridge), "--config", str(config_path), "disconnect"], timeout=25, env=env)
        write_text(out / "disconnect-source.txt", f"exit={code2}\n{output2}\n")
    if proc and proc.poll() is None:
        try:
            proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def run_capture_env(cmd: list[str], *, timeout: int = 20, input_text: str | None = None, env: dict | None = None) -> tuple[int, str]:
    try:
        result = subprocess.run(cmd, input=input_text, text=True, capture_output=True, timeout=timeout, env=env)
        return result.returncode, redact((result.stdout or "") + (result.stderr or ""))
    except subprocess.TimeoutExpired as exc:
        return 124, redact((exc.stdout or "") + (exc.stderr or "") + f"\nTIMEOUT after {timeout}s: {command_text(cmd)}")


def app_parity(args, *, source: bool = False, bypass_network_check: bool = False) -> int:
    out = run_dir("source-app-live" if source and bypass_network_check else "source-app-parity" if source else "app-parity")
    config_path = Path(args.config)
    started = time.time()
    report: dict = {
        "mode": "source-live" if source and bypass_network_check else "source" if source else "installed",
        "bypassNetworkCheck": bypass_network_check,
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        "configPath": str(config_path),
        "programData": str(PROGRAMDATA),
        "paths": app_installed_paths(),
        "installedBridgeVersion": bridge_version(Path(r"C:\Program Files\MyVpnClient\myvpnclient_bridge.py")),
        "sourceBridgeVersion": bridge_version(ROOT / "myvpnclient_bridge.py"),
        "config": {
            key: load_json(config_path).get(key)
            for key in [
                "name",
                "server",
                "backend",
                "useOpenconnectBackend",
                "preferDtls",
                "enableExperimentalDtls",
                "tapInterfaceAlias",
                "tapInterfaceMetric",
                "postConnectNetworkFix",
                "networkCheckDnsHost",
                "connectivityCheckHosts",
                "keepTunnelAliveWhileAppRunning",
            ]
            if key in load_json(config_path)
        },
        "progress": [],
    }
    write_text(out / "start-report.json", json.dumps(report, indent=2))

    pid_file = PROGRAMDATA_STATE / "openconnect.pid"
    existing_pid = read_pid_file(pid_file)
    if pid_running(existing_pid):
        report["ok"] = False
        report["error"] = f"Existing tunnel PID {existing_pid} is already running; disconnect it before app-parity."
        write_text(out / "app-parity-report.json", json.dumps(report, indent=2))
        print_live(str(out))
        return 3

    owner_file = PROGRAMDATA_STATE / "myvpnclient-owner.pid"
    previous_owner = owner_file.read_text(encoding="utf-8", errors="replace") if owner_file.exists() else ""
    previous_owner_pid = read_pid_file(owner_file)
    PROGRAMDATA_STATE.mkdir(parents=True, exist_ok=True)
    owner_file.write_text(str(os.getpid()), encoding="utf-8")
    proc = None
    stdout_lines: list[str] = []
    stdout_thread = None

    try:
        if source:
            proc, launch = launch_source_app_like(out, config_path, bypass_network_check=bypass_network_check)
            if proc and proc.stdout:
                def reader() -> None:
                    for line in proc.stdout:
                        stdout_lines.append(line)
                stdout_thread = threading.Thread(target=reader, daemon=True)
                stdout_thread.start()
        else:
            launch = launch_installed_app_like(out, started)
        report["launch"] = launch
        if not launch.get("ok"):
            report["ok"] = False
            write_text(out / "app-parity-report.json", json.dumps(report, indent=2))
            print_live(str(out))
            return 2

        state_path = PROGRAMDATA_STATE / "myvpn_tunnel.json"
        ready_seen = False
        terminal_seen = False
        deadline = time.time() + max(30, int(args.duration_seconds))
        last_state = {}
        stale_state_logged = False
        while time.time() < deadline:
            state = read_json_safe(state_path)
            if state and not state.get("_error"):
                state_epoch = local_time_epoch(state.get("time"))
                try:
                    state_mtime = state_path.stat().st_mtime
                except OSError:
                    state_mtime = 0.0
                state_fresh = (
                    (state_epoch is not None and state_epoch >= started - 2.0)
                    or (state_epoch is None and state_mtime >= started - 2.0)
                )
                if not state_fresh:
                    if not stale_state_logged:
                        report["progress"].append({
                            "t": round(time.time() - started, 1),
                            "ignoredStaleStatus": str(state.get("status") or ""),
                            "ignoredStaleTime": str(state.get("time") or ""),
                        })
                        stale_state_logged = True
                    time.sleep(2)
                    continue

                last_state = state
                status = str(state.get("status") or "")
                note = str(state.get("note") or "")
                report["progress"].append({"t": round(time.time() - started, 1), "status": status, "note": note})
                if status == "network-ready":
                    ready_seen = True
                    break
                if status in {"auth-failed", "auth-timeout", "tunnel-open-failed", "network-check-failed", "tunnel-stalled", "negotiation-timeout"}:
                    terminal_seen = True
                    break
            if proc and proc.poll() is not None:
                report["progress"].append({"t": round(time.time() - started, 1), "processExit": proc.returncode})
                break
            time.sleep(2)

        report["readySeen"] = ready_seen
        report["terminalSeen"] = terminal_seen
        report["lastState"] = last_state
        collect_snapshot(out / "live-snapshot", config_path)
        if ready_seen:
            report["jiraProbe"] = jira_vpn_probe(out, config_path, since=started, label="app-parity-live-jira")
        else:
            report["jiraProbe"] = {"ok": False, "skipped": "network-ready was not reached"}

    finally:
        write_text(out / "source-stdout.txt", "".join(stdout_lines))
        try:
            stop_app_like(out, config_path, proc)
        except Exception as exc:
            report["disconnectError"] = repr(exc)
        if previous_owner and pid_running(previous_owner_pid):
            owner_file.write_text(previous_owner, encoding="utf-8")
        else:
            try:
                owner_file.unlink()
            except OSError:
                pass
        if source:
            run_capture(["schtasks.exe", "/Delete", "/TN", "MyVpnClient-SourceConnect", "/F"], timeout=10)
        if stdout_thread:
            stdout_thread.join(timeout=3)

    report["elapsedSeconds"] = round(time.time() - started, 1)
    report["postState"] = read_json_safe(PROGRAMDATA_STATE / "myvpn_tunnel.json")
    collect_snapshot(out / "post-snapshot", config_path)
    report["ok"] = bool(report.get("readySeen")) and bool(report.get("jiraProbe", {}).get("ok"))
    write_text(out / "app-parity-report.json", json.dumps(report, indent=2))
    print_live(str(out))
    return 0 if report["ok"] else 2


def source_app_parity(args) -> int:
    return app_parity(args, source=True)


def source_app_live(args) -> int:
    return app_parity(args, source=True, bypass_network_check=True)


def apply_myvpn_overrides(args, config: dict) -> dict:
    applied: dict[str, object] = {}
    if getattr(args, "prefer_dtls", False):
        config["preferDtls"] = True
        config["enableExperimentalDtls"] = True
        applied["preferDtls"] = True
    if getattr(args, "windows_resolver", False):
        config["networkCheckUseWindowsResolver"] = True
        applied["windowsResolver"] = True
    if getattr(args, "disable_post_connect_network_fix", False):
        config["postConnectNetworkFix"] = False
        applied["disablePostConnectNetworkFix"] = True
    if getattr(args, "keepalive", False):
        config["keepTunnelAliveWhileAppRunning"] = True
        applied["keepAlive"] = True
    if getattr(args, "trace_packets", False):
        config["tracePackets"] = True
        applied["tracePackets"] = True
    if getattr(args, "no_fast_data_path", False):
        config["fastDataPath"] = False
        applied["fastDataPath"] = False
    if getattr(args, "force_onlink_jira", False):
        applied["forceOnlinkJira"] = True
    if applied:
        config["_sandboxOptions"] = applied
    return config


def myvpn_lab_config_path(args, out: Path, bridge, *, filename: str = "native-config.json") -> tuple[dict, Path]:
    config = bridge.load_config(Path(args.config))
    apply_myvpn_overrides(args, config)
    config_path = out / filename
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config, config_path


def myvpn_full(args) -> int:
    out = run_dir("myvpn-full")
    lab_state = out / "state"
    bridge = load_bridge(lab_state)
    config, config_path = myvpn_lab_config_path(args, out, bridge, filename="myvpn-full-config.json")
    started = time.time()
    code = bridge.full_diagnostic(config_path)
    elapsed = time.time() - started
    write_text(out / "summary.txt", f"exit={code}\nelapsed={elapsed:.1f}s\nstate={lab_state}\n")
    collect_snapshot(out / "post-snapshot", config_path)
    incremental_probe(out, config_path, label="after-myvpn-full")
    print_live(str(out))
    return code


def probe(args) -> int:
    out = run_dir("probe")
    report = incremental_probe(out, Path(args.config), label="manual")
    print_live(str(out))
    return 0 if report.get("ok") else 2



def first_failed_step(report: dict) -> str:
    for step in report.get("steps", []):
        if not step.get("ok"):
            return str(step.get("name") or "unknown")
    return ""


def native_stage(args, stage: str) -> int:
    out = run_dir(f"native-{stage}")
    lab_state = out / "state"
    print_live(str(out))
    print_live(f"MyVpn native-{stage}: run folder created")
    bridge = load_bridge(lab_state)
    config, config_path = myvpn_lab_config_path(args, out, bridge)
    config["useOpenconnectBackend"] = False
    config["diagnosticStopAfterNetworkCheck"] = True
    config["diagnosticNetworkCheckAttempts"] = 1
    config["diagnosticNetworkCheckTimeoutSeconds"] = 8
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    print_live(f"MyVpn native-{stage}: starting tunnel stage test; approve MFA when FortiToken push appears")
    stop_tail = threading.Event()
    tail_thread = threading.Thread(target=live_tail_mypvn_state, args=(lab_state, stop_tail), daemon=True)
    tail_thread.start()
    started = time.time()
    try:
        code = bridge.connect_myvpn_once(config)
    finally:
        stop_tail.set()
        tail_thread.join(timeout=2)
    elapsed = time.time() - started
    print_live(f"MyVpn native-{stage}: tunnel stage finished exit={code} elapsed={elapsed:.1f}s")
    collect_snapshot(out / "post-snapshot", config_path)
    report = incremental_probe(out, config_path, label=f"native-{stage}")
    fail = first_failed_step(report)
    summary = {
        "stage": stage,
        "exit": code,
        "elapsedSeconds": round(elapsed, 1),
        "probeOk": report.get("ok"),
        "firstFailedStep": fail,
        "state": str(lab_state),
    }
    write_text(out / "summary.json", json.dumps(summary, indent=2))
    print_live(str(out))

    if stage == "ppp":
        return 0 if any(step.get("name") == "adapter-ip" and step.get("ok") for step in report.get("steps", [])) else 2
    if stage == "dns":
        wanted = [step for step in report.get("steps", []) if step.get("name", "").startswith("dns-")]
        return 0 if wanted and any(step.get("ok") for step in wanted) else 2
    if stage == "tcp":
        return 0 if any(step.get("name", "").startswith("tcp-jira") and step.get("ok") for step in report.get("steps", [])) else 2
    if stage == "https":
        return 0 if any(step.get("name", "").startswith("https-jira") and step.get("ok") for step in report.get("steps", [])) else 2
    return 0 if report.get("ok") else 2


def native_ppp(args) -> int:
    return native_stage(args, "ppp")


def native_dns(args) -> int:
    return native_stage(args, "dns")


def native_tcp(args) -> int:
    # Keep the tunnel up while probing Jira. The old stop-after-network-check
    # flow produced misleading post-disconnect reports through public Wi-Fi.
    return native_tcp_live(args, force_onlink=False, label="native-tcp")


def native_tcp_onlink(args) -> int:
    return native_tcp_live(args, force_onlink=True)


def native_https(args) -> int:
    return native_tcp_live(args, force_onlink=False, require_https=True, label="native-https")


def native_tcp_live(args, *, force_onlink: bool = False, require_https: bool = False, label: str | None = None) -> int:
    run_label = label or ("native-tcp-onlink" if force_onlink else "native-tcp-live")
    out = run_dir(run_label)
    lab_state = out / "state"
    bridge = load_bridge(lab_state)
    config, config_path = myvpn_lab_config_path(args, out, bridge)
    config["useOpenconnectBackend"] = False
    config["diagnosticStopAfterNetworkCheck"] = False
    config["networkCheckAttempts"] = 1
    config["networkCheckDelaySeconds"] = 1
    config["networkCheckRouteWaitSeconds"] = 5
    config["networkCheckDnsTimeoutSeconds"] = 3
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    force_onlink = force_onlink or bool(getattr(args, "force_onlink_jira", False))

    bridge.OWNER_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    bridge.OWNER_PID_FILE.write_text(str(os.getpid()), encoding="utf-8")

    print_live(str(out))
    print_live(f"MyVpn {run_label}: run folder created")
    print_live(f"MyVpn {run_label}: starting live tunnel probe; approve MFA when FortiToken push appears")
    stop_tail = threading.Event()
    tail_thread = threading.Thread(target=live_tail_mypvn_state, args=(lab_state, stop_tail), daemon=True)
    tail_thread.start()

    original_verify = bridge.verify_myvpn_network_ready
    original_owner_is_gone = bridge.owner_is_gone
    stop_tunnel = threading.Event()
    bridge.verify_myvpn_network_ready = lambda cfg, vpn_cfg, ipv4: (True, "sandbox bypass: hold native tunnel for live TCP probe")
    bridge.owner_is_gone = lambda: stop_tunnel.is_set() or original_owner_is_gone()

    result: dict[str, object] = {"exit": None}

    def runner() -> None:
        try:
            result["exit"] = bridge.connect_myvpn_once(config)
        except BaseException as exc:
            result["error"] = repr(exc)

    thread = threading.Thread(target=runner, name="native-tcp-live-tunnel", daemon=True)
    started = time.time()
    thread.start()

    ready = False
    for _ in range(max(1, args.duration_seconds)):
        state_file = lab_state / "myvpn_tunnel.json"
        trace_file = lab_state / "myvpn_tunnel-current-trace.jsonl"
        try:
            state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}
        except json.JSONDecodeError:
            state = {}
        trace_tail = trace_file.read_text(encoding="utf-8", errors="replace")[-20000:] if trace_file.exists() else ""
        state_ready = state.get("status") == "network-ready" and bool(str(state.get("ipv4", "")))
        trace_ready = '"status": "network-ready"' in trace_tail
        if state_ready or trace_ready:
            ready = True
            break
        if not thread.is_alive():
            break
        time.sleep(1)

    checks = {
        "adapter": not args.skip_live_adapter_check,
        "route": not args.skip_live_route_check,
        "tcp": not args.skip_live_tcp_check,
        "https": require_https and not args.skip_live_https_check,
    }
    report = {"label": run_label, "ready": ready, "requireHttps": require_https, "checks": checks, "steps": []}
    progress_file = out / f"{safe_name(run_label)}-progress.txt"

    def progress(message: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {message}"
        with progress_file.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        print_live(f"MyVpn {run_label}: {message}")

    progress(f"ready={ready} thread_alive={thread.is_alive()} result={result}")

    def skip_step(name: str, reason: str) -> None:
        report["steps"].append({"name": name, "skipped": True, "ok": True, "reason": reason})
        progress(f"skip {name}: {reason}")

    def live_step(name: str, script: str, timeout: int = 15, ok_contains: list[str] | None = None) -> None:
        progress(f"start {name}")
        code, output = ps(script, timeout=timeout)
        ok = code == 0 and all(token in output for token in (ok_contains or []))
        item = {"name": name, "exit": code, "ok": ok, "output": output[-5000:]}
        report["steps"].append(item)
        write_text(out / f"native-tcp-live-{safe_name(name)}.txt", f"exit={code}\nok={ok}\n{output}\n")
        progress(f"done {name} exit={code} ok={ok}")

    def python_tcp_step(host: str, port: int, timeout: float = 8.0) -> None:
        name = f"python-tcp-{host}-{port}"
        progress(f"start {name}")
        started_step = time.time()
        ok = False
        detail = ""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                ok = True
                detail = "connected"
        except Exception as exc:
            detail = repr(exc)
        elapsed = round(time.time() - started_step, 3)
        item = {"name": name, "exit": 0 if ok else 1, "ok": ok, "elapsed": elapsed, "output": detail}
        report["steps"].append(item)
        write_text(out / f"native-tcp-live-{safe_name(name)}.txt", f"ok={ok}\nelapsed={elapsed}\n{detail}\n")
        progress(f"done {name} ok={ok} elapsed={elapsed}")

    try:
        if ready:
            jira_host = str(config.get("probeHost") or config.get("jiraCheckHost") or "")
            jira_ip = str(config.get("probeIp") or config.get("jiraCheckIp") or jira_host)
            progress(f"strict_private_jira host={jira_host} ip={jira_ip}")
            if checks["adapter"]:
                live_step(
                    "adapter-ip-live",
                    "Get-NetIPAddress -InterfaceAlias 'Local Area Connection' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength | ConvertTo-Json -Depth 4",
                    ok_contains=[],
                )
            else:
                skip_step("adapter-ip-live", "adapter check disabled")
            if checks["route"]:
                live_step(
                    "route-jira-live",
                    f"$ip='{jira_ip}'; Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Select @{{Name='RemoteAddress';Expression={{$ip}}}},DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric | ConvertTo-Json -Depth 4",
                    ok_contains=["Local Area Connection"],
                )
            else:
                skip_step("route-jira-live", "route check disabled")
            if force_onlink:
                live_step(
                    "force-onlink-jira-route",
                    f"$ip='{jira_ip}'; $prefix=\"$ip/32\"; $if=(Get-NetIPInterface -InterfaceAlias 'Local Area Connection' -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1).InterfaceIndex; Remove-NetRoute -DestinationPrefix $prefix -InterfaceIndex $if -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $if -NextHop '0.0.0.0' -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Select DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric | ConvertTo-Json -Depth 4",
                    timeout=15,
                    ok_contains=["0.0.0.0", "Local Area Connection"],
                )
            if checks["tcp"]:
                python_tcp_step(jira_ip, 443, timeout=20.0)
            else:
                skip_step(f"python-tcp-{jira_ip}-443", "TCP check disabled")
            if checks["tcp"]:
                live_step(
                    "tcp-jira-live",
                    f"$ip='{jira_ip}'; $started=Get-Date; $c=New-Object Net.Sockets.TcpClient; $iar=$c.BeginConnect($ip,443,$null,$null); $ok=$iar.AsyncWaitHandle.WaitOne(20000,$false); if ($ok) {{ try {{ $c.EndConnect($iar); $connected=$true }} catch {{ $connected=$false; $err=$_.Exception.Message }} }} else {{ $connected=$false; $err='timeout' }}; $elapsed=[math]::Round(((Get-Date)-$started).TotalSeconds,3); $c.Close(); [pscustomobject]@{{Host='{jira_host}';Address=$ip;Connected=$connected;ElapsedSeconds=$elapsed;Error=$err}}|ConvertTo-Json -Depth 3",
                    timeout=25,
                    ok_contains=["true"],
                )
            else:
                skip_step("tcp-jira-live", "TCP check disabled")
            if checks["https"]:
                live_step(
                    "https-jira-live",
                    f"$started=Get-Date; $outFile=Join-Path $env:TEMP 'myvpn-sandbox-jira-live.html'; Remove-Item -LiteralPath $outFile -ErrorAction SilentlyContinue; curl.exe -k --fail-with-body --noproxy '*' --resolve {jira_host}:443:{jira_ip} --connect-timeout 20 --max-time 90 -sS -w '\nCURL_HTTP_CODE=%{{http_code}}\nCURL_TIME_CONNECT=%{{time_connect}}\nCURL_TIME_APPCONNECT=%{{time_appconnect}}\nCURL_TIME_TOTAL=%{{time_total}}\n' -D - https://{jira_host}/ -o $outFile; $code=$LASTEXITCODE; $plain=''; if (Test-Path $outFile) {{ $body=Get-Content $outFile -Raw -ErrorAction SilentlyContinue; $plain=($body -replace '<script[\\s\\S]*?</script>',' ' -replace '<style[\\s\\S]*?</style>',' ' -replace '<[^>]+>',' ' -replace '\\s+',' ').Trim(); if ($plain.Length -gt 500) {{ $plain=$plain.Substring(0,500) }} }}; $elapsed=[math]::Round(((Get-Date)-$started).TotalSeconds,3); [pscustomobject]@{{CurlExit=$code;ElapsedSeconds=$elapsed;Preview=$plain}}|ConvertTo-Json -Depth 4; exit $code",
                    timeout=120,
                    ok_contains=["CurlExit"],
                )
            else:
                skip_step("https-jira-live", "HTTPS check disabled")
            hold_until = started + max(1, int(args.duration_seconds))
            while thread.is_alive() and time.time() < hold_until:
                remaining = max(0, int(hold_until - time.time()))
                progress(f"holding tunnel open for browser checks; {remaining}s remaining")
                time.sleep(min(10, max(1, remaining)))

    except BaseException as exc:
        report["probeError"] = repr(exc)
        progress(f"probe_error {type(exc).__name__}: {exc}")
    finally:
        write_text(out / "native-tcp-live-report.partial.json", json.dumps(report, indent=2))
        progress("stop requested")
        stop_tunnel.set()
        try:
            bridge.OWNER_PID_FILE.write_text("0", encoding="utf-8")
            report["stopSignal"] = "owner-stop-event-and-pid-stale"
        except OSError as exc:
            report["stopSignalError"] = repr(exc)
    thread.join(timeout=20)
    bridge.verify_myvpn_network_ready = original_verify
    bridge.owner_is_gone = original_owner_is_gone
    progress(f"thread_join_done alive={thread.is_alive()} result={result}")
    try:
        bridge.OWNER_PID_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    stop_tail.set()
    tail_thread.join(timeout=2)
    report["tunnelExit"] = result
    report["threadAliveAfterJoin"] = thread.is_alive()
    report["elapsedSeconds"] = round(time.time() - started, 1)
    tcp_ok = any(step.get("name") == "tcp-jira-live" and step.get("ok") for step in report["steps"])
    https_ok = any(step.get("name") == "https-jira-live" and step.get("ok") for step in report["steps"])
    report["tcpOk"] = tcp_ok
    report["httpsOk"] = https_ok
    report["ok"] = ready and (https_ok if checks["https"] else tcp_ok if checks["tcp"] else True)
    write_text(out / f"{safe_name(run_label)}-report.json", json.dumps(report, indent=2))
    collect_snapshot(out / "post-snapshot", config_path)
    write_text(out / f"{safe_name(run_label)}-report.json", json.dumps(report, indent=2))
    if run_label != "native-tcp-live":
        write_text(out / "native-tcp-live-report.json", json.dumps(report, indent=2))
    print_live(str(out))
    return 0 if report["ok"] else 2

def openconnect_auth(args) -> int:
    out = run_dir("openconnect-auth")
    bridge = load_bridge(out / "state")
    config = bridge.load_config(Path(args.config))
    password = bridge.load_dpapi_password()
    cmd = [
        "openconnect",
        "--protocol=fortinet",
        "--authenticate",
        "--user=" + str(config["username"]),
        "--passwd-on-stdin",
        "--disable-ipv6",
        "--timestamp",
        str(config["server"]),
    ]
    code, output = run_capture(cmd, timeout=args.duration_seconds, input_text=password + "\n\n\n\n")
    write_text(out / "openconnect-auth.txt", f"$ {command_text(cmd)}\nexit={code}\n{output}\n")
    print_live(str(out))
    return 0 if code == 0 else code


def openconnect_connect(args) -> int:
    out = run_dir("openconnect-connect")
    bridge = load_bridge(out / "state")
    config = bridge.load_config(Path(args.config))
    password = bridge.load_dpapi_password()
    cmd = [
        "openconnect",
        "--protocol=fortinet",
        "--user=" + str(config["username"]),
        "--passwd-on-stdin",
        "--disable-ipv6",
        "--timestamp",
        "--verbose",
        "--interface=Local Area Connection",
        r"--script=C:\Program Files\OpenConnect\vpnc-script-win.js",
        str(config["server"]),
    ]
    write_text(out / "command.txt", command_text(cmd) + "\n")
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    assert proc.stdin is not None
    proc.stdin.write(password + "\n\n\n\n")
    proc.stdin.flush()

    q: queue.Queue[str] = queue.Queue()
    def reader() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            q.put(line)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    log_lines: list[str] = []
    deadline = time.time() + args.duration_seconds
    try:
        while time.time() < deadline and proc.poll() is None:
            try:
                line = q.get(timeout=1)
                log_lines.append(line)
                print(redact(line), end="")
            except queue.Empty:
                pass
            if any("Legacy IP route configuration done" in line for line in log_lines[-20:]):
                break
        collect_snapshot(out / "live-snapshot", Path(args.config))
        time.sleep(3)
        collect_snapshot(out / "after-3s-snapshot", Path(args.config))
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        while not q.empty():
            log_lines.append(q.get_nowait())
        write_text(out / "openconnect.log", "".join(log_lines) + f"\nexit={proc.returncode}\n")
    print_live(str(out))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="MyVpnClient source-run VPN lab")
    parser.add_argument("command", choices=["preflight", "collect", "compare-sources", "myvpn-full", "probe", "native-ppp", "native-dns", "native-tcp", "native-tcp-live", "native-tcp-onlink", "native-https", "openconnect-auth", "openconnect-connect", "app-parity", "source-app-parity", "source-app-live"])
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--openconnect-source", default=str(DEFAULT_OPENCONNECT_SOURCE))
    parser.add_argument("--duration-seconds", type=int, default=90)
    parser.add_argument("--prefer-dtls", action="store_true", help="Enable experimental DTLS in the temporary MyVpn run config")
    parser.add_argument("--force-onlink-jira", action="store_true", help="Force the configured probe IP route as on-link TAP route during live MyVpn probes")
    parser.add_argument("--windows-resolver", action="store_true", help="Allow Windows resolver fallback during MyVpn network checks")
    parser.add_argument("--disable-post-connect-network-fix", action="store_true", help="Disable postConnectNetworkFix in the temporary MyVpn run config")
    parser.add_argument("--keepalive", action="store_true", help="Set keepTunnelAliveWhileAppRunning in the temporary MyVpn run config")
    parser.add_argument("--trace-packets", action="store_true", help="Enable packet/flow trace events in the temporary MyVpn run config")
    parser.add_argument("--no-fast-data-path", action="store_true", help="Disable MyVpn PPP fast data path for A/B comparison")
    parser.add_argument("--skip-live-adapter-check", action="store_true", help="Skip adapter IP check during native live runs")
    parser.add_argument("--skip-live-route-check", action="store_true", help="Skip target route check during native live runs")
    parser.add_argument("--skip-live-tcp-check", action="store_true", help="Skip target TCP checks during native live runs")
    parser.add_argument("--skip-live-https-check", action="store_true", help="Skip target HTTPS/curl check during native live runs")
    args = parser.parse_args()
    return {
        "preflight": preflight,
        "collect": collect,
        "compare-sources": compare_sources,
        "myvpn-full": myvpn_full,
        "probe": probe,
        "native-ppp": native_ppp,
        "native-dns": native_dns,
        "native-tcp": native_tcp,
        "native-tcp-live": native_tcp_live,
        "native-tcp-onlink": native_tcp_onlink,
        "native-https": native_https,
        "openconnect-auth": openconnect_auth,
        "openconnect-connect": openconnect_connect,
        "app-parity": app_parity,
        "source-app-parity": source_app_parity,
        "source-app-live": source_app_live,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
