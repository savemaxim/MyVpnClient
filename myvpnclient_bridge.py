#!/usr/bin/env python3
"""MyVpnClient bridge: integrated Fortinet SSL VPN tunnel helper."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import ctypes
from ctypes import wintypes
import ipaddress
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR / "backend"
if BACKEND_DIR.is_dir():
    sys.path.insert(0, str(BACKEND_DIR))

from myvpn_tunnel.engine import (
    BACKEND_NAME,
    DtlsUnavailable,
    FortinetClient,
    FortinetDtlsTransport,
    FortinetPppEngine,
    FortinetTlsTunnel,
    open_packet_adapter,
    packet_adapter_available,
    summarize_config,
)

DATA_DIR = Path(os.environ.get("MYVPNCLIENT_DATA_DIR") or APP_DIR)
DEFAULT_CONFIG = DATA_DIR / "config.json"
STATE_DIR = DATA_DIR / "state"
PID_FILE = STATE_DIR / "openconnect.pid"
OWNER_PID_FILE = STATE_DIR / "myvpnclient-owner.pid"
MYVPN_STATE_FILE = STATE_DIR / "myvpn_tunnel.json"
LOG_FILE = STATE_DIR / "myvpn.log"
ACTIVE_LOG_FILE = LOG_FILE
LEGACY_LOG_FILE = STATE_DIR / "openconnect.log"
TRACE_DIR = STATE_DIR / "traces"
DIAGNOSTICS_DIR = STATE_DIR / "diagnostics"
CURRENT_TRACE_FILE = STATE_DIR / "myvpn_tunnel-current-trace.jsonl"
RUN_TRACE_FILE: Path | None = None
MYVPN_ROUTES_FILE = STATE_DIR / "myvpn_tunnel-routes.json"
NETWORK_TRANSACTION_FILE = STATE_DIR / "myvpn_tunnel-network-transaction.json"
HOST_OVERRIDES_STATE_FILE = STATE_DIR / "myvpn_tunnel-host-overrides.json"
DEFAULT_TAP_ALIAS = "Local Area Connection"
DEFAULT_OPENCONNECT_ALIAS = "MyVpnClient"
HOSTS_BLOCK_BEGIN = "# MyVpnClient VPN host overrides begin"
HOSTS_BLOCK_END = "# MyVpnClient VPN host overrides end"
DEFAULT_VPN_DNS: list[str] = []
BACKEND_MYVPN = BACKEND_NAME
MYVPNCLIENT_VERSION = "1.0.133"
AUTH_SUCCESS_MARKERS = (
    "Session authentication will expire",
    "ESP session established",
    "DTLS handshake complete",
    "CSTP connected",
    "Connected as ",
)
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
ROUTE_CHECK_TIMEOUT_SECONDS = 30
SENSITIVE_TEXT_RE = re.compile(r"(?i)(password|pass|token|secret|cookie|credential|key)\s*[:=]\s*([^\r\n,;]+)")
LEGACY_CONFIG_KEYS: dict[str, str] = {}


def normalize_config_keys(config: dict) -> dict:
    for current, legacy in LEGACY_CONFIG_KEYS.items():
        if current not in config and legacy in config:
            config[current] = config[legacy]
        config.pop(legacy, None)
    return config


def config_value(config: dict, key: str, default=None):
    if key in config:
        return config.get(key)
    legacy = LEGACY_CONFIG_KEYS.get(key)
    if legacy and legacy in config:
        return config.get(legacy)
    return default


def load_config(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"Config not found: {path}\nCopy config.example.json to config.json and edit it.")
    with path.open("r", encoding="utf-8") as handle:
        data = normalize_config_keys(json.load(handle))
    if not data.get("server"):
        raise SystemExit("Config field 'server' is required.")
    configure_log_path(data)
    return data


def load_dpapi_password() -> str:
    secret_path = STATE_DIR / "password.dpapi"
    if os.name != "nt" or not secret_path.exists():
        return ""
    try:
        return dpapi_unprotect(secret_path.read_bytes()).decode("utf-8")
    except Exception as exc:
        trace_event("password_unprotect_failed", error=str(exc))
        return ""


class DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def dpapi_unprotect(protected_bytes: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    input_buffer = ctypes.create_string_buffer(protected_bytes)
    input_blob = DataBlob(
        len(protected_bytes),
        ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    output_blob = DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)


def backend_name(config: dict) -> str:
    return BACKEND_MYVPN


def base_url_from_server(server: str) -> str:
    server = server.strip()
    if "://" not in server:
        server = "https://" + server
    return server.rstrip("/")


def read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return None


def read_owner_pid() -> int | None:
    try:
        return int(OWNER_PID_FILE.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return None


def is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                check=False,
            )
            return f'"{pid}"' in result.stdout or f",{pid}," in result.stdout
        except OSError:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def require_admin_for_windows() -> None:
    if os.name == "nt" and not is_admin():
        raise SystemExit(
            "MyVpnClient needs Administrator privileges on Windows to create/open "
            "the Wintun/TAP adapter and install routes.\n"
            "Run PowerShell as Administrator, or use .\\connect-admin.ps1."
        )


def configured_log_path(config: dict) -> Path:
    configured = str(config_value(config, "logPath", "") or "").strip()
    if not configured:
        return LOG_FILE
    path = Path(configured).expanduser()
    if not path.is_absolute():
        path = DATA_DIR / path
    if path.exists() and path.is_dir():
        path = path / "myvpn.log"
    elif not path.suffix:
        path = path / "myvpn.log"
    return path


def configure_log_path(config: dict) -> None:
    global ACTIVE_LOG_FILE
    ACTIVE_LOG_FILE = configured_log_path(config)


def log_line_with_timestamp(message: str) -> str:
    text = message.rstrip()
    if not text:
        return ""
    if re.match(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]", text) or text.startswith("openconnect: [") or text.startswith("--- "):
        return text
    return f"[{now_text()}] {text}"


def append_log(message: str) -> None:
    path = ACTIVE_LOG_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as log:
        log.write((log_line_with_timestamp(message) + "\n").encode("utf-8", errors="replace"))
        log.flush()


def readable_log_file() -> Path:
    if ACTIVE_LOG_FILE.exists() or ACTIVE_LOG_FILE != LOG_FILE:
        return ACTIVE_LOG_FILE
    if LOG_FILE.exists() or not LEGACY_LOG_FILE.exists():
        return LOG_FILE
    return LEGACY_LOG_FILE


def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def trace_event(event: str, **fields) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    payload = {
        "time": now_text(),
        "event": event,
        **fields,
    }
    line = json.dumps(payload, ensure_ascii=True, sort_keys=True)
    targets = [CURRENT_TRACE_FILE]
    if RUN_TRACE_FILE is not None and RUN_TRACE_FILE != CURRENT_TRACE_FILE:
        targets.append(RUN_TRACE_FILE)
    for target in targets:
        try:
            target.parent.mkdir(exist_ok=True)
            with target.open("ab") as handle:
                handle.write((line + "\n").encode("utf-8", errors="replace"))
        except OSError as exc:
            append_log(f"myvpn_tunnel trace write failed for {target}: {exc}")


def start_trace() -> None:
    global RUN_TRACE_FILE
    TRACE_DIR.mkdir(exist_ok=True)
    if CURRENT_TRACE_FILE.exists():
        archived = TRACE_DIR / f"myvpn_tunnel-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
        try:
            CURRENT_TRACE_FILE.replace(archived)
        except OSError:
            CURRENT_TRACE_FILE.unlink(missing_ok=True)
    RUN_TRACE_FILE = TRACE_DIR / f"myvpn_tunnel-run-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}.jsonl"
    RUN_TRACE_FILE.unlink(missing_ok=True)
    trace_event("connect_start", version=MYVPNCLIENT_VERSION, backend=BACKEND_MYVPN, python=sys.version.split()[0], traceFile=str(RUN_TRACE_FILE))

def write_myvpn_state(config: dict, status: str, note: str, **fields) -> None:
    previous = {}
    try:
        previous = json.loads(MYVPN_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        previous = {}
    mfa_status = fields.pop("mfaStatus", previous.get("mfaStatus", ""))
    connected_at = fields.pop("connectedAt", previous.get("connectedAt", ""))
    if status == "network-ready" and not connected_at:
        connected_at = now_text()
    elif status != "network-ready":
        connected_at = ""
    payload = {
        "status": status,
        "server": config.get("server", ""),
        "pid": os.getpid(),
        "time": now_text(),
        "note": note,
        "stats": previous.get("stats", {}),
        "mfaStatus": mfa_status,
        "connectedAt": connected_at,
        **fields,
    }
    MYVPN_STATE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    trace_event("state", status=status, note=note, mfaStatus=mfa_status, connectedAt=connected_at, **fields)


def classify_myvpn_auth_failure(result) -> str:
    messages = " ".join(result.messages).lower()
    if "tokeninfo" in messages or "mfa" in messages or "logincheck" in messages:
        return "MFA approval was not accepted, expired, or did not produce a VPN cookie."
    if result.status == "authentication-required":
        return "Fortinet still requires authentication; no VPN cookie was issued."
    return f"Fortinet authentication failed with status {result.status}; no VPN cookie was issued."


def encode_dns_name(name: str) -> bytes:
    labels = [part.encode("ascii") for part in name.rstrip(".").split(".") if part]
    if not labels or any(len(label) > 63 for label in labels):
        raise ValueError(f"Invalid DNS name: {name}")
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def read_dns_name(message: bytes, offset: int, *, depth: int = 0) -> tuple[str, int]:
    if depth > 8:
        return "", offset
    labels: list[str] = []
    cursor = offset
    jumped = False
    next_offset = offset
    while cursor < len(message):
        length = message[cursor]
        if length == 0:
            cursor += 1
            if not jumped:
                next_offset = cursor
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                return ".".join(labels), len(message)
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            suffix, _ = read_dns_name(message, pointer, depth=depth + 1)
            if suffix:
                labels.append(suffix)
            cursor += 2
            if not jumped:
                next_offset = cursor
            jumped = True
            break
        cursor += 1
        label = message[cursor:cursor + length]
        labels.append(label.decode("ascii", errors="replace"))
        cursor += length
        if not jumped:
            next_offset = cursor
    return ".".join(labels), next_offset


def parse_dns_a_response(message: bytes, expected_id: int) -> tuple[int, list[str]]:
    if len(message) < 12:
        raise ValueError("DNS response is shorter than header")
    dns_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", message[:12])
    if dns_id != expected_id:
        raise ValueError(f"DNS response id mismatch: expected {expected_id}, got {dns_id}")
    rcode = flags & 0x000F
    cursor = 12
    for _ in range(qdcount):
        _name, cursor = read_dns_name(message, cursor)
        cursor += 4
    answers: list[str] = []
    for _ in range(ancount):
        _name, cursor = read_dns_name(message, cursor)
        if cursor + 10 > len(message):
            break
        rr_type, rr_class, _ttl, rdlength = struct.unpack("!HHIH", message[cursor:cursor + 10])
        cursor += 10
        rdata = message[cursor:cursor + rdlength]
        cursor += rdlength
        if rr_type == 1 and rr_class == 1 and rdlength == 4:
            answers.append(".".join(str(part) for part in rdata))
    return rcode, answers



def wait_for_dns_route_ready(dns_server: str, interface_alias: str, timeout: float) -> tuple[bool, str]:
    if os.name != "nt":
        return True, "non-Windows route check skipped"
    deadline = time.monotonic() + max(0.0, timeout)
    last_detail = ""
    alias_escaped = str(interface_alias).replace("'", "''")
    dns_escaped = str(dns_server).replace("'", "''")
    while True:
        code, output = run_text([
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"$alias='{alias_escaped}'; $dns='{dns_escaped}'; "
            "$tap=Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1; "
            "$exact=$null; if ($tap) { $exact=Get-NetRoute -InterfaceIndex $tap.InterfaceIndex -DestinationPrefix ($dns + '/32') -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 }; "
            "$r=Find-NetRoute -RemoteIPAddress $dns -ErrorAction SilentlyContinue | Sort-Object {$_.RouteMetric + $_.InterfaceMetric} | Select-Object -First 1; "
            "$i=$null; if ($r) { $i=Get-NetIPInterface -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 }; "
            "[pscustomobject]@{exactRoute=$exact.DestinationPrefix; exactNextHop=$exact.NextHop; exactMetric=$exact.RouteMetric; exactInterface=$tap.InterfaceAlias; route=$r.DestinationPrefix; interface=$i.InterfaceAlias; routeMetric=$r.RouteMetric; interfaceMetric=$i.InterfaceMetric; nextHop=$r.NextHop} | ConvertTo-Json -Depth 4",
        ], timeout=5)
        last_detail = output.strip()
        trace_event("network_check_dns_route", dns=dns_server, exit_code=code, detail=last_detail)
        route_interface = ""
        if code == 0 and last_detail:
            try:
                route_payload = json.loads(last_detail)
                if isinstance(route_payload, dict):
                    route_interface = str(route_payload.get("exactInterface") or route_payload.get("interface") or "")
            except json.JSONDecodeError:
                route_interface = ""
        if route_interface.lower() == interface_alias.lower():
            return True, last_detail
        if time.monotonic() >= deadline:
            return False, last_detail or "route not found"
        time.sleep(1.0)
def query_dns_a_direct(host: str, dns_server: str, timeout: float, bind_ip: str = "") -> tuple[bool, str, list[str]]:
    query_id = (os.getpid() + int(time.time() * 1000)) & 0xFFFF
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + encode_dns_name(host) + struct.pack("!HH", 1, 1)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        if bind_ip:
            sock.bind((bind_ip, 0))
        trace_event("network_check_dns_probe_start", host=host, dns=dns_server, timeoutSeconds=timeout, bindIp=bind_ip)
        sent = sock.sendto(packet, (dns_server, 53))
        local = ""
        try:
            local = f"{sock.getsockname()[0]}:{sock.getsockname()[1]}"
        except OSError:
            pass
        trace_event("network_check_dns_probe_sent", host=host, dns=dns_server, local=local, bytes=sent, queryId=query_id)
        while True:
            data, remote = sock.recvfrom(4096)
            elapsed = round(time.monotonic() - started, 3)
            if remote[0] != dns_server:
                trace_event("network_check_dns_probe_ignored", host=host, dns=dns_server, remote=remote[0], elapsedSeconds=elapsed)
                continue
            try:
                rcode, answers = parse_dns_a_response(data, query_id)
            except ValueError as exc:
                trace_event("network_check_dns_probe_ignored", host=host, dns=dns_server, error=str(exc), elapsedSeconds=elapsed)
                continue
            detail = f"rcode={rcode}; answers={','.join(answers) or '-'}; elapsed={elapsed}s"
            trace_event("network_check_dns_probe", host=host, dns=dns_server, local=local, rcode=rcode, answers=answers, elapsedSeconds=elapsed)
            return rcode == 0 and bool(answers), detail, answers



def event_is_recent(event: dict, since_seconds: float) -> bool:
    if since_seconds <= 0:
        return True
    stamp = str(event.get("time") or "").strip()
    if not stamp:
        return False
    try:
        event_time = time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return False
    return time.time() - event_time <= since_seconds


def observed_vpn_dns_traffic(dns_servers: list[str], since_seconds: float = 30.0) -> bool:
    wanted = {str(server).strip() for server in dns_servers if str(server).strip()}
    if not wanted:
        return False
    for event in trace_tail(limit=800, path=RUN_TRACE_FILE or CURRENT_TRACE_FILE):
        if event.get("event") != "dns_packet" or event.get("direction") != "rx":
            continue
        if not event_is_recent(event, since_seconds):
            continue
        if str(event.get("src") or "").strip() in wanted:
            return True
    return False


def observed_dns_answers(hosts: list[str], since_seconds: float = 90.0) -> tuple[bool, str, list[str]]:
    wanted = {host.rstrip(".").lower() for host in hosts if host}
    if not wanted:
        return False, "", []
    answers: list[str] = []
    matched_host = ""
    saw_reply = False
    for event in trace_tail(limit=800, path=RUN_TRACE_FILE or CURRENT_TRACE_FILE):
        if event.get("event") != "dns_packet" or event.get("direction") != "rx":
            continue
        if not event_is_recent(event, since_seconds):
            continue
        qname = str(event.get("qname") or "").rstrip(".").lower()
        if qname not in wanted:
            continue
        if int(event.get("rcode") or 0) != 0:
            continue
        saw_reply = True
        matched_host = qname
        answer = str(event.get("answerA") or "").strip()
        if answer:
            answers.extend([item.strip() for item in answer.split(",") if item.strip()])
    answers = list(dict.fromkeys(answers))
    if answers:
        return True, matched_host, answers
    if saw_reply:
        return True, matched_host, []
    return False, "", []

def remember_dynamic_routes(config: dict, routes: list[str]) -> None:
    if not routes:
        return
    try:
        payload = json.loads(MYVPN_ROUTES_FILE.read_text(encoding="utf-8")) if MYVPN_ROUTES_FILE.exists() else {}
    except (OSError, json.JSONDecodeError):
        payload = {}
    existing = [str(route) for route in payload.get("routes", []) if route] if isinstance(payload, dict) else []
    changed = False
    for route in routes:
        if route not in existing:
            existing.append(route)
            changed = True
    if changed:
        if not isinstance(payload, dict):
            payload = {}
        payload["interface"] = payload.get("interface") or config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
        payload["routes"] = existing
        payload["time"] = now_text()
        MYVPN_ROUTES_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def install_tap_host_routes(config: dict, addresses: list[str], reason: str = "resolved-host", *, allow_public: bool = False) -> list[str]:
    if os.name != "nt":
        return []
    routes: list[str] = []
    for address in addresses:
        try:
            ip = ipaddress.IPv4Address(str(address))
        except ValueError:
            continue
        is_private = (
            ip in ipaddress.IPv4Network("10.0.0.0/8")
            or ip in ipaddress.IPv4Network("172.16.0.0/12")
            or ip in ipaddress.IPv4Network("192.168.0.0/16")
        )
        if not is_private and not allow_public:
            trace_event("network_check_host_route_skipped", reason=reason, address=str(ip), classification="non-rfc1918")
            continue
        routes.append(f"{ip}/32")
    routes = list(dict.fromkeys(routes))
    if not routes:
        return []
    alias = str(config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS).replace("'", "''")
    route_literal = "@(" + ",".join("'" + route.replace("'", "''") + "'" for route in routes) + ")"
    script = f"""
$ErrorActionPreference = 'Continue'
$alias = '{alias}'
$ifInfo = Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
$ifIndex = [int]$ifInfo.InterfaceIndex
$tapIp = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object {{ $_.IPAddress -and $_.IPAddress -notlike '169.254.*' }} |
  Select-Object -First 1 -ExpandProperty IPAddress
$gateway = '0.0.0.0'
$fallbackGateway = '0.0.0.0'
$routes = {route_literal}
$installed = @()
foreach ($route in $routes) {{
  $parts = $route.Split('/')
  $ip = $parts[0]
  Remove-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $route -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  & route.exe DELETE $ip MASK 255.255.255.255 $fallbackGateway IF $ifIndex 2>&1 | Out-Null
  & route.exe DELETE $ip MASK 255.255.255.255 0.0.0.0 IF $ifIndex 2>&1 | Out-Null
  & route.exe ADD $ip MASK 255.255.255.255 $gateway METRIC 1 IF $ifIndex 2>&1 | Out-Null
  New-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $route -NextHop $gateway -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
  $exact = Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $route -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object {{ $_.NextHop -eq $gateway }} |
    Select-Object -First 1
  if (-not $exact -and $fallbackGateway -ne $gateway) {{
    & route.exe ADD $ip MASK 255.255.255.255 $fallbackGateway METRIC 1 IF $ifIndex 2>&1 | Out-Null
    New-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $route -NextHop $fallbackGateway -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
    $exact = Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $route -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
      Where-Object {{ $_.NextHop -eq $fallbackGateway }} |
      Select-Object -First 1
  }}
  if ($exact) {{
    $installed += $route
  }}
}}
Clear-DnsClientCache
"gateway=$gateway;fallbackGateway=$fallbackGateway;installed=$($installed -join ',')"
"""
    code, output = run_text(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=8)
    output_clean = output.replace("\r", "").strip()
    installed_text = output_clean.split("installed=", 1)[1] if "installed=" in output_clean else output_clean
    installed = [item.strip() for item in installed_text.split(",") if item.strip() and "/" in item]
    if installed:
        remember_dynamic_routes(config, installed)
    trace_event("network_check_host_routes", reason=reason, exit_code=code, requested=routes, installed=installed, output=output_clean[:500])
    return installed


def usable_connectivity_hosts(hosts: list[str]) -> list[str]:
    blocked: set[str] = set()
    result: list[str] = []
    for host in hosts:
        normalized = str(host).strip().rstrip(".").lower()
        if not normalized or normalized in blocked:
            continue
        result.append(normalized)
    return list(dict.fromkeys(result))


def query_dns_a_windows(host: str, dns_server: str, timeout: float) -> tuple[bool, str, list[str]]:
    escaped_host = host.replace("'", "''")
    escaped_server = dns_server.replace("'", "''")
    trace_event("network_check_dns_windows_start", host=host, dns=dns_server, timeoutSeconds=timeout)
    script = (
        f"Resolve-DnsName '{escaped_host}' -Server '{escaped_server}' -Type A -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress | ConvertTo-Json -Depth 3"
    )
    code, output = run_text(["powershell.exe", "-NoProfile", "-Command", script], timeout=max(8, int(timeout) + 5))
    answers: list[str] = []
    if code == 0 and output.strip():
        try:
            payload = json.loads(output)
            if isinstance(payload, str):
                answers = [payload]
            elif isinstance(payload, list):
                answers = [str(item) for item in payload if item]
        except json.JSONDecodeError:
            answers = [line.strip() for line in output.splitlines() if line.strip() and not line.strip().startswith("{")]
    detail = f"exit={code}; answers={','.join(answers) or '-'}"
    trace_event("network_check_dns_windows", host=host, dns=dns_server, exit_code=code, answers=answers, output=output.strip()[:500])
    return code == 0 and bool(answers), detail, answers


def query_dns_a_default(host: str, timeout: float) -> tuple[bool, str, list[str]]:
    escaped_host = host.replace("'", "''")
    trace_event("network_check_dns_default_start", host=host, timeoutSeconds=timeout)
    script = (
        f"Resolve-DnsName '{escaped_host}' -Type A -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress | ConvertTo-Json -Depth 3"
    )
    code, output = run_text(["powershell.exe", "-NoProfile", "-Command", script], timeout=max(8, int(timeout) + 5))
    answers: list[str] = []
    if code == 0 and output.strip():
        try:
            payload = json.loads(output)
            if isinstance(payload, str):
                answers = [payload]
            elif isinstance(payload, list):
                answers = [str(item) for item in payload if item]
        except json.JSONDecodeError:
            answers = [line.strip() for line in output.splitlines() if line.strip() and not line.strip().startswith("{")]
    detail = f"exit={code}; answers={','.join(answers) or '-'}"
    trace_event("network_check_dns_default", host=host, exit_code=code, answers=answers, output=output.strip()[:500])
    return code == 0 and bool(answers), detail, answers


def is_private_ipv4(value: object) -> bool:
    try:
        ip = ipaddress.IPv4Address(str(value))
    except ValueError:
        return False
    return (
        ip in ipaddress.IPv4Network("10.0.0.0/8")
        or ip in ipaddress.IPv4Network("172.16.0.0/12")
        or ip in ipaddress.IPv4Network("192.168.0.0/16")
    )


def private_ipv4_answers(answers: list[str]) -> list[str]:
    private_answers: list[str] = []
    for answer in answers:
        try:
            ip = ipaddress.IPv4Address(str(answer))
        except ValueError:
            continue
        if is_private_ipv4(ip):
            private_answers.append(str(ip))
    return private_answers


def normalize_vpn_host_overrides(config: dict, hosts: list[str]) -> dict[str, str]:
    enabled = config.get("vpnHostOverridesEnabled", True)
    if isinstance(enabled, str) and enabled.strip().lower() in {"0", "false", "no", "off"}:
        return {}
    if enabled is False:
        return {}

    overrides: dict[str, str] = {}
    raw = config.get("vpnHostOverrides") or config.get("vpnStaticHostOverrides") or {}
    items: list[tuple[str, object]] = []
    if isinstance(raw, dict):
        items.extend((str(host), value) for host, value in raw.items())
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                host = item.get("host") or item.get("name")
                address = item.get("ip") or item.get("address")
                if host and address:
                    items.append((str(host), address))
            elif isinstance(item, str) and "=" in item:
                host, address = item.split("=", 1)
                items.append((host, address))
    elif isinstance(raw, str):
        for item in re.split(r"[;,\n]+", raw):
            if "=" in item:
                host, address = item.split("=", 1)
                items.append((host, address))

    for host, address in items:
        normalized_host = host.strip().rstrip(".").lower()
        try:
            ip = str(ipaddress.IPv4Address(str(address).strip()))
        except ValueError:
            trace_event("vpn_host_override_ignored", host=normalized_host, address=str(address), reason="invalid-ip")
            continue
        if not normalized_host or not is_private_ipv4(ip):
            trace_event("vpn_host_override_ignored", host=normalized_host, address=ip, reason="not-private")
            continue
        overrides[normalized_host] = ip

    return overrides


def windows_hosts_file() -> Path:
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"


def strip_managed_hosts_block(text: str) -> tuple[str, bool]:
    lines = text.splitlines()
    cleaned: list[str] = []
    in_block = False
    removed = False
    for line in lines:
        if line.strip() == HOSTS_BLOCK_BEGIN:
            in_block = True
            removed = True
            continue
        if line.strip() == HOSTS_BLOCK_END:
            in_block = False
            continue
        if not in_block:
            cleaned.append(line)
    return "\n".join(cleaned).strip() + ("\n" if cleaned else ""), removed


def install_vpn_host_overrides(config: dict, overrides: dict[str, str], *, reason: str) -> list[str]:
    if os.name != "nt" or not overrides:
        return []
    normalized = normalize_vpn_host_overrides({"vpnHostOverrides": overrides}, list(overrides.keys()))
    if not normalized:
        return []
    hosts_path = windows_hosts_file()
    try:
        original = hosts_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        trace_event("vpn_host_overrides_failed", reason=reason, error=f"read: {exc}")
        return []
    stripped, _ = strip_managed_hosts_block(original)
    block = [
        HOSTS_BLOCK_BEGIN,
        "# Managed by MyVpnClient while the VPN tunnel is connected.",
        *[f"{address}\t{host}" for host, address in sorted(normalized.items())],
        HOSTS_BLOCK_END,
        "",
    ]
    new_text = "\n".join(block) + stripped
    try:
        hosts_path.write_text(new_text, encoding="utf-8")
        HOST_OVERRIDES_STATE_FILE.write_text(json.dumps({"time": now_text(), "reason": reason, "hosts": normalized}, indent=2), encoding="utf-8")
        run_text(["powershell.exe", "-NoProfile", "-Command", "Clear-DnsClientCache"], timeout=6)
    except OSError as exc:
        trace_event("vpn_host_overrides_failed", reason=reason, error=f"write: {exc}", hosts=normalized)
        return []
    installed = [f"{host}={address}" for host, address in sorted(normalized.items())]
    trace_event("vpn_host_overrides_installed", reason=reason, hosts=installed)
    return installed


def cleanup_vpn_host_overrides(*, reason: str) -> None:
    if os.name != "nt":
        return
    hosts_path = windows_hosts_file()
    try:
        original = hosts_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        trace_event("vpn_host_overrides_cleanup_failed", reason=reason, error=f"read: {exc}")
        return
    stripped, removed = strip_managed_hosts_block(original)
    if not removed:
        HOST_OVERRIDES_STATE_FILE.unlink(missing_ok=True)
        trace_event("vpn_host_overrides_cleanup", reason=reason, removed=False)
        return
    try:
        hosts_path.write_text(stripped, encoding="utf-8")
        HOST_OVERRIDES_STATE_FILE.unlink(missing_ok=True)
        run_text(["powershell.exe", "-NoProfile", "-Command", "Clear-DnsClientCache"], timeout=6)
        trace_event("vpn_host_overrides_cleanup", reason=reason, removed=True)
    except OSError as exc:
        trace_event("vpn_host_overrides_cleanup_failed", reason=reason, error=f"write: {exc}")


def tcp_connect_check(target: str, port: int, timeout: float) -> tuple[bool, str]:
    started = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            elapsed = time.monotonic() - started
            return True, f"ok elapsed={elapsed:.3f}s"
    except OSError as exc:
        elapsed = time.monotonic() - started
        return False, f"{type(exc).__name__}: {exc}; elapsed={elapsed:.3f}s"


def tap_routed_ipv4_answers(config: dict, answers: list[str], reason: str) -> list[str]:
    if os.name != "nt":
        return []
    alias = str(config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS)
    alias_escaped = alias.replace("'", "''")
    routed: list[str] = []
    for answer in answers:
        try:
            ip = ipaddress.IPv4Address(str(answer))
        except ValueError:
            continue
        address = str(ip)
        address_escaped = address.replace("'", "''")
        script = f"""
$alias = '{alias_escaped}'
$address = '{address_escaped}'
$tap = Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
$exact = $null
if ($tap) {{
  $exact = Get-NetRoute -InterfaceIndex $tap.InterfaceIndex -DestinationPrefix ($address + '/32') -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
}}
$route = $null
$iface = $null
if (-not $exact) {{
  $route = Find-NetRoute -RemoteIPAddress $address -ErrorAction SilentlyContinue |
    Where-Object {{ $_.DestinationPrefix }} |
    Sort-Object @{{Expression={{ if ($null -ne $_.RouteMetric) {{ [int]$_.RouteMetric }} else {{ 9999 }} }} }}, @{{Expression={{ if ($null -ne $_.InterfaceMetric) {{ [int]$_.InterfaceMetric }} else {{ 9999 }} }} }} |
    Select-Object -First 1
  if ($route) {{
    $iface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
  }}
}}
[pscustomobject]@{{
  address = $address
  exactRoute = $exact.DestinationPrefix
  exactNextHop = $exact.NextHop
  exactMetric = $exact.RouteMetric
  exactInterface = if ($exact -and $tap) {{ $tap.InterfaceAlias }} else {{ $null }}
  route = $route.DestinationPrefix
  routeInterface = $iface.InterfaceAlias
  routeNextHop = $route.NextHop
  routeMetric = $route.RouteMetric
  interfaceMetric = $route.InterfaceMetric
}} | ConvertTo-Json -Depth 4
"""
        code, output = run_text(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=6)
        detail = output.strip()
        trace_event("network_check_answer_route", reason=reason, address=address, exit_code=code, detail=detail[:500])
        if code != 0 or not detail:
            continue
        try:
            payload = json.loads(detail)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        exact_interface = str(payload.get("exactInterface") or "")
        route_interface = str(payload.get("routeInterface") or "")
        if exact_interface.lower() == alias.lower() or route_interface.lower() == alias.lower():
            routed.append(address)
    return list(dict.fromkeys(routed))


def verify_myvpn_network_ready(config: dict, vpn_config, bind_ip: str = "") -> tuple[bool, str]:
    trace_event("network_check_skipped", reason="host checks removed from MyVpnClient")
    return True, "host checks disabled"

def current_myvpn_state_name() -> str:
    try:
        state = json.loads(MYVPN_STATE_FILE.read_text(encoding="utf-8"))
        return str(state.get("status") or "")
    except (OSError, json.JSONDecodeError):
        return ""


def is_myvpn_terminal_state(state: str) -> bool:
    return state in {
        "auth-failed",
        "auth-timeout",
        "tunnel-open-failed",
        "tunnel-lost",
        "negotiation-timeout",
        "network-check-failed",
        "tunnel-stalled",
    }


def apply_windows_network_fix(config: dict, wait_for_ip: bool = True) -> int:
    if os.name != "nt":
        print("Network fix is only needed on Windows.")
        return 0

    require_admin_for_windows()

    interface_alias = config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
    dns_servers = config.get("vpnDnsServers") or DEFAULT_VPN_DNS
    if isinstance(dns_servers, str):
        dns_servers = [item.strip() for item in dns_servers.split(",") if item.strip()]
    metric = int(config.get("tapInterfaceMetric") or 1)
    timeout_seconds = int(config.get("networkFixWaitSeconds") or 90)

    dns_literal = ",".join(f"'{server}'" for server in dns_servers)
    dns_script = (
        f"Set-DnsClientServerAddress -InterfaceAlias '{interface_alias}' -ServerAddresses @({dns_literal})"
        if dns_servers
        else f"Write-Output \"No VPN DNS servers configured; leaving DNS servers unchanged for {interface_alias}.\""
    )
    wait_script = ""
    if wait_for_ip:
        wait_script = f"""
$deadline = (Get-Date).AddSeconds({timeout_seconds})
while ((Get-Date) -lt $deadline) {{
  $ip = Get-NetIPAddress -InterfaceAlias '{interface_alias}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($ip) {{ break }}
  Start-Sleep -Seconds 2
}}
"""

    ps_script = f"""
$ErrorActionPreference = 'Continue'
{wait_script}
{dns_script}
Set-NetIPInterface -InterfaceAlias '{interface_alias}' -AddressFamily IPv4 -InterfaceMetric {metric}
ipconfig /flushdns | Out-Null
$dns = (Get-DnsClientServerAddress -InterfaceAlias '{interface_alias}' -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ','
$iface = Get-NetIPInterface -InterfaceAlias '{interface_alias}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
Write-Output "Applied VPN DNS/route fix: interface={interface_alias}; dns=$dns; metric=$($iface.InterfaceMetric)"
"""

    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (result.stdout + result.stderr).strip()
    if output:
        print(output)
        append_log(output)
    return result.returncode


def start_network_fix_thread(config: dict) -> None:
    if os.name != "nt" or not config.get("postConnectNetworkFix", True):
        return

    def worker() -> None:
        try:
            append_log("--- applying post-connect DNS/route fix ---")
            apply_windows_network_fix(config, wait_for_ip=True)
        except Exception as exc:
            append_log(f"Post-connect DNS/route fix failed: {exc}")

    threading.Thread(target=worker, name="vpn-network-fix", daemon=True).start()


def terminate_process_tree(pid: int) -> None:
    if os.name == "nt":
        try:
            os.kill(pid, signal.CTRL_BREAK_EVENT)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                if not is_running(pid):
                    return
                time.sleep(0.5)
        except OSError as exc:
            append_log(f"Graceful VPN stop failed for PID {pid}: {exc}")
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], check=False)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass


def cleanup_tap_public_host_routes(config: dict, *, reason: str) -> None:
    if os.name != "nt":
        return
    interface_alias = config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
    alias_literal = str(interface_alias).replace("'", "''")
    ps_script = f"""
$ErrorActionPreference = 'Continue'
$alias = '{alias_literal}'
$routes = @(Get-NetRoute -InterfaceAlias $alias -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
  Where-Object {{
    $_.DestinationPrefix -match '^\\d+\\.\\d+\\.\\d+\\.\\d+/32$' -and
    $_.DestinationPrefix -notlike '10.*' -and
    $_.DestinationPrefix -notlike '172.16.*' -and
    $_.DestinationPrefix -notlike '172.17.*' -and
    $_.DestinationPrefix -notlike '172.18.*' -and
    $_.DestinationPrefix -notlike '172.19.*' -and
    $_.DestinationPrefix -notlike '172.2?.*' -and
    $_.DestinationPrefix -notlike '172.30.*' -and
    $_.DestinationPrefix -notlike '172.31.*' -and
    $_.DestinationPrefix -notlike '192.168.*'
  }})
foreach ($route in $routes) {{
  Remove-NetRoute -InterfaceAlias $alias -DestinationPrefix $route.DestinationPrefix -NextHop $route.NextHop -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  & route.exe DELETE ($route.DestinationPrefix -replace '/32','') MASK 255.255.255.255 0.0.0.0 IF $route.ifIndex 2>&1 | Out-Null
}}
$routes | Select-Object -ExpandProperty DestinationPrefix
"""
    code, output = run_powershell(ps_script, timeout=10)
    removed = [line.strip() for line in output.replace("\r", "").splitlines() if line.strip()]
    if removed:
        append_log(f"Removed stale public TAP host routes after {reason}: {', '.join(removed)}")
    trace_event("tap_public_host_routes_cleanup", reason=reason, exit_code=code, removed=removed)


def cleanup_windows_network_state(config: dict, *, reason: str) -> None:
    if os.name != "nt":
        return
    try:
        require_admin_for_windows()
    except SystemExit as exc:
        append_log(f"Skipping VPN network cleanup after {reason}: {exc}")
        return

    interface_alias = route_tracking_interface_alias(config)
    tracked_routes = []
    transaction = {}
    try:
        tracked = json.loads(MYVPN_ROUTES_FILE.read_text(encoding="utf-8"))
        if isinstance(tracked, dict):
            tracked_interface = str(tracked.get("interface") or "").strip()
            if tracked_interface:
                interface_alias = tracked_interface
            tracked_routes = [str(route) for route in tracked.get("routes", []) if route]
    except (OSError, json.JSONDecodeError):
        tracked_routes = []
    alias_literal = str(interface_alias).replace("'", "''")
    try:
        transaction = json.loads(NETWORK_TRANSACTION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        transaction = {}
    tracked_route_literal = "@(" + ",".join("'" + route.replace("'", "''") + "'" for route in tracked_routes) + ")"
    original_dns = []
    if isinstance(transaction, dict) and transaction.get("interface") == interface_alias:
        original_dns = [str(item) for item in transaction.get("dns", []) if item]
    original_dns_literal = "@(" + ",".join("'" + server.replace("'", "''") + "'" for server in original_dns) + ")"
    broad_cleanup = backend_name(config) != BACKEND_MYVPN or "manual reset" in reason or "stale PID" in reason
    broad_literal = "$true" if broad_cleanup else "$false"
    ps_script = f"""
$ErrorActionPreference = 'Continue'
$alias = '{alias_literal}'
$trackedRoutes = {tracked_route_literal}
if ($trackedRoutes.Count -gt 0) {{
  $routes = @(Get-NetRoute -InterfaceAlias $alias -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object {{ $trackedRoutes -contains $_.DestinationPrefix }})
}} elseif ({broad_literal}) {{
  $routes = @(Get-NetRoute -InterfaceAlias $alias -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object {{ $_.DestinationPrefix -ne '0.0.0.0/0' }})
}} else {{
  $routes = @()
}}
foreach ($route in $routes) {{
  Remove-NetRoute -InterfaceAlias $alias -DestinationPrefix $route.DestinationPrefix -NextHop $route.NextHop -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}}
$ips = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue)
foreach ($ip in $ips) {{
  Remove-NetIPAddress -InterfaceAlias $alias -IPAddress $ip.IPAddress -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}}
$originalDns = {original_dns_literal}
if ($originalDns.Count -gt 0) {{
  Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $originalDns -ErrorAction SilentlyContinue
}} else {{
  Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses -ErrorAction SilentlyContinue
}}
Write-Output "Cleaned VPN network state after {reason}: interface=$alias; removedRoutes=$($routes.Count); removedIPv4=$($ips.Count); restoredDns=$($originalDns -join ',')"
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (result.stdout + result.stderr).strip()
    if output:
        append_log(output)
    cleanup_vpn_host_overrides(reason=reason)
    MYVPN_ROUTES_FILE.unlink(missing_ok=True)
    NETWORK_TRANSACTION_FILE.unlink(missing_ok=True)


def capture_network_transaction(config: dict) -> None:
    if os.name != "nt":
        return
    cleanup_vpn_host_overrides(reason="pre-connect capture")
    cleanup_tap_public_host_routes(config, reason="pre-connect capture")
    interface_alias = config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
    alias_literal = str(interface_alias).replace("'", "''")
    ps_script = f"""
$alias = '{alias_literal}'
$dns = @((Get-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
$ips = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
$routes = @(Get-NetRoute -InterfaceAlias $alias -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DestinationPrefix)
[pscustomobject]@{{interface=$alias; dns=$dns; ips=$ips; routes=$routes}} | ConvertTo-Json -Depth 5
"""
    code, output = run_powershell(ps_script, timeout=10)
    if code == 0 and output.strip():
        try:
            payload = json.loads(output)
            payload["time"] = now_text()
            NETWORK_TRANSACTION_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            trace_event("network_transaction_captured", interface=interface_alias)
        except json.JSONDecodeError as exc:
            append_log(f"Network transaction capture parse failed: {exc}")


def start_network_transaction_capture(config: dict) -> threading.Thread | None:
    if os.name != "nt":
        return None
    if not config_bool(config, "preConnectNetworkCapture", False):
        trace_event("network_transaction_capture_skipped", reason="disabled")
        append_log("myvpn_tunnel pre-connect network cleanup/snapshot skipped (preConnectNetworkCapture=false).")
        return None
    config_snapshot = dict(config)
    interface_alias = config_snapshot.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS

    def worker() -> None:
        started = time.monotonic()
        append_log("myvpn_tunnel pre-connect network cleanup/snapshot started.")
        trace_event("network_transaction_capture_start", interface=interface_alias)
        try:
            capture_network_transaction(config_snapshot)
            elapsed_ms = int((time.monotonic() - started) * 1000)
            append_log(f"myvpn_tunnel pre-connect network cleanup/snapshot finished in {elapsed_ms} ms.")
            trace_event("network_transaction_capture_done", interface=interface_alias, elapsedMs=elapsed_ms)
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            append_log(f"myvpn_tunnel pre-connect network cleanup/snapshot failed after {elapsed_ms} ms: {exc}")
            trace_event("network_transaction_capture_failed", interface=interface_alias, elapsedMs=elapsed_ms, error=str(exc))

    thread = threading.Thread(target=worker, name="myvpn-preconnect-network-capture", daemon=True)
    thread.start()
    return thread


class LazyPacketAdapter:
    def __init__(self, kind: str, alias: str) -> None:
        self.kind = kind
        self.alias = alias
        self._adapter = None
        self._lock = threading.Lock()

    def _open(self):
        with self._lock:
            if self._adapter is None:
                started = time.monotonic()
                append_log(f"myvpn_tunnel opening packet adapter '{self.alias}' ({self.kind}) at PPP network-ready.")
                trace_event("packet_adapter_open_start", adapterKind=self.kind, interface=self.alias)
                self._adapter = open_packet_adapter(self.kind, self.alias, log=append_log)
                elapsed_ms = int((time.monotonic() - started) * 1000)
                trace_event("packet_adapter_opened", adapterKind=self.kind, interface=self.alias, elapsedMs=elapsed_ms)
        return self._adapter

    def configure(self, *args, **kwargs):
        return self._open().configure(*args, **kwargs)

    def start_reader(self, *args, **kwargs):
        return self._open().start_reader(*args, **kwargs)

    def write(self, packet: bytes) -> int:
        if self._adapter is None:
            return 0
        return self._adapter.write(packet)

    def close(self) -> None:
        adapter = self._adapter
        if adapter is not None:
            adapter.close()
            self._adapter = None


def route_to_prefix(route: str) -> str:
    if "/" not in route:
        return route
    address, mask = route.split("/", 1)
    try:
        prefix = ipaddress.IPv4Network((address, mask), strict=False).prefixlen
        return f"{address}/{prefix}"
    except ValueError:
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            return f"{address}/{prefix}"
        except ValueError:
            return route



def effective_vpn_routes(config: dict, vpn_config) -> list[str]:
    routes = list(vpn_config.routes if vpn_config else [])
    extra = config.get("vpnIncludeRoutes") or config.get("vpnPublicRoutes") or []
    if isinstance(extra, str):
        extra = [item.strip() for item in extra.split(",") if item.strip()]
    if not isinstance(extra, list):
        extra = []
    return list(dict.fromkeys([*routes, *[str(item).strip() for item in extra if str(item).strip()]]))

def remember_myvpn_routes(config: dict, ipv4: str, routes: list[str], dns: list[str]) -> None:
    route_prefixes = [route_to_prefix(route) for route in routes if route]
    route_prefixes.extend(f"{server}/32" for server in dns if server and ":" not in server)
    route_prefixes = list(dict.fromkeys(route for route in route_prefixes if route))
    payload = {
        "interface": route_tracking_interface_alias(config),
        "ipv4": ipv4,
        "routes": route_prefixes,
        "dns": dns,
        "time": now_text(),
    }
    MYVPN_ROUTES_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    trace_event("network_routes_tracked", routes=len(route_prefixes), dns=dns)



def claim_vpn_pid() -> tuple[bool, str]:
    STATE_DIR.mkdir(exist_ok=True)
    while True:
        try:
            fd = os.open(str(PID_FILE), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(str(os.getpid()))
            return True, ""
        except FileExistsError:
            existing = read_pid()
            if existing and is_running(existing):
                return False, f"Another MyVpnClient tunnel is already running with PID {existing}. Disconnect it before connecting again."
            PID_FILE.unlink(missing_ok=True)
        except OSError as exc:
            return False, f"Could not claim VPN PID file {PID_FILE}: {exc}"

def start_owner_watch_thread(process: subprocess.Popen, config: dict) -> None:
    owner_pid = read_owner_pid()
    if not owner_pid:
        return
    if not is_running(owner_pid):
        append_log(f"Ignoring stale MyVpnClient owner PID {owner_pid} for VPN PID {process.pid}.")
        return

    def worker() -> None:
        while process.poll() is None:
            if not is_running(owner_pid):
                append_log(
                    f"MyVpnClient owner process {owner_pid} is gone; stopping VPN PID {process.pid}."
                )
                trace_event("owner_gone", owner_pid=owner_pid, tunnel_pid=process.pid)
                terminate_process_tree(process.pid)
                cleanup_windows_network_state(config, reason="owner process exited")
                return
            time.sleep(2)

    threading.Thread(target=worker, name="myvpnclient-owner-watch", daemon=True).start()


def owner_is_gone() -> bool:
    owner_pid = read_owner_pid()
    if not owner_pid:
        return False
    gone = not is_running(owner_pid)
    if gone:
        trace_event("owner_gone", owner_pid=owner_pid)
    return gone


def keepalive_enabled(config: dict) -> bool:
    return bool(config.get("keepTunnelAliveWhileAppRunning", False))


def keepalive_delay(config: dict) -> float:
    return max(1.0, float(config.get("keepTunnelAliveReconnectDelaySeconds") or 10))


def keepalive_max_reconnects(config: dict) -> int:
    return max(0, int(config.get("keepTunnelAliveMaxReconnects") or 0))


def should_reconnect_after_exit(config: dict, exit_code: int, reconnects: int, state: str = "") -> bool:
    if not keepalive_enabled(config):
        return False
    if owner_is_gone():
        append_log("Persistent tunnel stopped because MyVpnClient owner is no longer running.")
        return False
    if exit_code == 0:
        append_log("Persistent tunnel stopped after clean disconnect.")
        return False
    if state in {"", "authenticated", "tunnel-open-failed"}:
        append_log("Persistent tunnel will not reconnect because tunnel setup did not complete.")
        return False
    if exit_code == 2 and state == "tunnel-lost":
        append_log("Persistent tunnel will reconnect after Fortinet rejected the OpenConnect cookie.")
    max_reconnects = keepalive_max_reconnects(config)
    if max_reconnects > 0 and reconnects >= max_reconnects:
        append_log(f"Persistent tunnel reconnect limit reached ({max_reconnects}).")
        return False
    return True

def state_metadata(state: str, detail: str = "") -> dict:
    mapping = {
        "disconnected": ("Idle", "VPN is disconnected.", "Connect when ready.", True),
        "authenticating": ("Authenticating", "MFA push sent; approve FortiToken on your phone.", "Keep this window open while waiting for the VPN cookie.", True),
        "authenticated": ("Authenticated", "VPN cookie received.", "Opening tunnel stream.", False),
        "tls-tunnel-running": ("OpeningTunnel", "TLS tunnel stream is open.", "Waiting for PPP negotiation.", False),
        "dtls-tunnel-running": ("OpeningTunnel", "DTLS tunnel stream is open.", "Waiting for PPP negotiation.", False),
        "running": ("OpeningTunnel", "Tunnel process is running.", "Waiting for tunnel state.", False),
        "ppp-lcp-start": ("NegotiatingPpp", "Starting PPP negotiation.", "Wait for LCP negotiation.", False),
        "ppp-lcp-opened": ("NegotiatingPpp", "PPP LCP is open.", "Waiting for network configuration.", False),
        "ppp-ipcp-start": ("NegotiatingPpp", "Negotiating VPN IPv4 settings.", "Wait for IPCP negotiation.", False),
        "ppp-terminating": ("Disconnecting", "Stopping PPP tunnel.", "Wait for disconnect cleanup.", False),
        "network-ready": ("NetworkReady", "VPN network is ready.", "No action needed.", False),
        "reconnect-wait": ("Reconnecting", "Tunnel dropped; reconnect is scheduled.", "Wait or disconnect to stop retrying.", False),
        "auth-failed": ("FailedAuth", "VPN authentication failed.", "Check username, password, MFA, and auth group.", True),
        "auth-timeout": ("FailedAuth", "VPN authentication timed out.", "Retry and approve MFA promptly.", True),
        "tunnel-open-failed": ("FailedTunnel", "VPN tunnel endpoint could not be opened.", "Run preflight and check server access.", True),
        "tunnel-lost": ("FailedTunnel", "VPN tunnel was lost.", "Retry or check network connectivity.", True),
        "negotiation-timeout": ("FailedTunnel", "PPP negotiation timed out.", "Retry, then run diagnostics if it repeats.", True),
        "network-check-failed": ("FailedNetwork", "VPN tunnel is up but traffic checks failed.", "Disconnect and reconnect; if it repeats, use OpenConnect while PPP/TAP is fixed.", True),
        "tunnel-stalled": ("FailedNetwork", "VPN tunnel stopped passing traffic.", "Run network repair or reconnect.", True),
    }
    phase, message, action, retryable = mapping.get(state, ("Unknown", detail or state, "Refresh status or run diagnostics.", True))
    if detail and phase not in {"Idle", "NetworkReady"}:
        message = detail
    return {
        "phase": phase,
        "userMessage": message,
        "suggestedAction": action,
        "retryable": retryable,
        "recoverability": "retryable" if retryable else "wait" if phase not in {"Idle", "NetworkReady"} else "none",
    }


def connect(config_path: Path, *, wait: bool = False) -> int:
    config = load_config(config_path)
    return connect_myvpn(config)


def connect_myvpn(config: dict) -> int:
    normalize_config_keys(config)
    if not keepalive_enabled(config):
        return connect_myvpn_once(config)

    reconnects = 0
    while True:
        trace_event("persistent_connect_start", backend=BACKEND_MYVPN, reconnects=reconnects)
        exit_code = connect_myvpn_once(config)
        state = current_myvpn_state_name()
        trace_event("persistent_connect_exit", backend=BACKEND_MYVPN, exit_code=exit_code, state=state, reconnects=reconnects)
        if state in {"auth-failed", "auth-timeout"}:
            append_log("Persistent tunnel will not reconnect after authentication failure.")
            return exit_code
        if state == "network-check-failed":
            append_log("Persistent tunnel will not reconnect after full network check failure.")
            return exit_code
        if not should_reconnect_after_exit(config, exit_code, reconnects, state):
            return exit_code
        reconnects += 1
        delay = keepalive_delay(config)
        append_log(f"Persistent myvpn_tunnel reconnect {reconnects} starting in {delay:.0f}s.")
        write_myvpn_state(config, "reconnect-wait", f"Tunnel dropped; reconnecting in {delay:.0f}s.", reconnects=reconnects)
        time.sleep(delay)




def config_bool(config: dict, key: str, default: bool = False) -> bool:
    value = config_value(config, key, default)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def config_int(config: dict, key: str, default: int = 0) -> int:
    try:
        return int(config_value(config, key, default) or 0)
    except (TypeError, ValueError):
        return default


def config_float(config: dict, key: str, default: float = 0.0) -> float:
    try:
        return float(config_value(config, key, default) or 0.0)
    except (TypeError, ValueError):
        return default


ET_MONTHS = {
    "jaanuari": 1,
    "veebruari": 2,
    "marts": 3,
    "aprill": 4,
    "mai": 5,
    "juuni": 6,
    "juuli": 7,
    "august": 8,
    "september": 9,
    "oktoober": 10,
    "november": 11,
    "detsember": 12,
}
SESSION_EXPIRY_RE = re.compile(r"Session authentication will expire at .*?,\s*(\d{1,2})\s+(\S+)\s+(\d{4})\s+(\d{2}:\d{2}:\d{2})", re.IGNORECASE)

def log_session_expiry_event(config: dict, expiry_at: datetime, phase: str, reason: str = "") -> None:
    expiry_text = expiry_at.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    if phase == "approaching":
        append_log(f"VPN authentication expires at {expiry_text}")
        trace_event("session_expiry_approaching", expiry=expiry_at.isoformat(), reason=reason)
    elif phase == "expired":
        suffix = f" ({reason})" if reason else ""
        append_log(f"VPN authentication expired at {expiry_text}{suffix}")
        trace_event("session_expiry_expired", expiry=expiry_at.isoformat(), reason=reason)

def parse_openconnect_session_expiry(line: str) -> datetime | None:
    match = SESSION_EXPIRY_RE.search(line)
    if not match:
        return None
    day_text, month_text, year_text, time_text = match.groups()
    month = ET_MONTHS.get(month_text.lower())
    if not month:
        return None
    try:
        hour, minute, second = (int(part) for part in time_text.split(":"))
        return datetime(int(year_text), month, int(day_text), hour, minute, second)
    except ValueError:
        return None



def openconnect_executable(config: dict) -> str:
    configured = str(config.get("openconnectPath") or "").strip()
    if configured:
        return configured
    bundled = APP_DIR / "OpenConnect" / "openconnect.exe"
    candidates = [
        str(bundled),
        r"C:\Program Files\OpenConnect\openconnect.exe",
        r"C:\Program Files (x86)\OpenConnect\openconnect.exe",
        "openconnect",
    ]
    for candidate in candidates:
        if candidate == "openconnect" or Path(candidate).exists():
            return candidate
    return "openconnect"


def openconnect_vpnc_script(config: dict) -> str:
    configured = str(config.get("openconnectScript") or "").strip()
    if configured:
        return configured
    bundled = APP_DIR / "OpenConnect" / "vpnc-script-win.js"
    if bundled.exists():
        return str(bundled)
    return r"C:\Program Files\OpenConnect\vpnc-script-win.js"


def openconnect_interface_alias(config: dict) -> str:
    configured = str(config.get("openconnectInterfaceAlias") or config.get("openconnectInterface") or "").strip()
    if configured:
        return configured
    native_alias = str(config.get("tapInterfaceAlias") or "").strip()
    if native_alias and native_alias.lower() != DEFAULT_TAP_ALIAS.lower():
        return native_alias
    return DEFAULT_OPENCONNECT_ALIAS


def openconnect_interface_arg_alias(config: dict) -> str:
    alias = openconnect_interface_alias(config)
    if config_bool(config, "openconnectForceInterfaceAlias", False):
        return alias
    if alias.lower() == DEFAULT_OPENCONNECT_ALIAS.lower():
        return ""
    return alias


def route_tracking_interface_alias(config: dict) -> str:
    if config_bool(config, "useOpenconnectBackend", False):
        return openconnect_interface_alias(config)
    return config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS


def config_with_openconnect_interface_alias(config: dict, alias: str) -> dict:
    runtime_config = dict(config)
    if alias:
        runtime_config["openconnectInterfaceAlias"] = alias
    return runtime_config


def parse_openconnect_adapter_alias(line: str) -> str:
    patterns = (
        r"\b(?:Using|Opened|Created)\s+(?:existing\s+)?(?:Wintun|TAP-Windows|TAP|tun)\s+(?:device|adapter)\s+['\"]([^'\"]+)['\"]",
        r"\b(?:Using|Opened|Created)\s+(?:interface|adapter)\s+['\"]([^'\"]+)['\"]",
    )
    for pattern in patterns:
        match = re.search(pattern, line, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def apply_openconnect_route_fix(config: dict, ipv4: str, routes: list[str], dns: list[str]) -> None:
    if os.name != "nt":
        return
    alias = openconnect_interface_alias(config).replace("'", "''")
    gateway = "0.0.0.0"
    route_prefixes = [route_to_prefix(route) for route in routes if route]
    route_prefixes.extend(f"{server}/32" for server in dns if server and ":" not in server)
    route_prefixes = list(dict.fromkeys(route for route in route_prefixes if route))
    route_literal = "@(" + ",".join("'" + route.replace("'", "''") + "'" for route in route_prefixes) + ")"
    dns_literal = "@(" + ",".join("'" + server.replace("'", "''") + "'" for server in dns if server) + ")"
    mtu = int(config.get("tapMtu") or 1351)
    ps_script = f"""
$ErrorActionPreference = 'Continue'
$alias = '{alias}'
$gateway = '{gateway}'
$routes = {route_literal}
$dns = {dns_literal}
$iface = Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
$ifIndex = [int]$iface.InterfaceIndex
& netsh.exe interface ipv4 set subinterface $ifIndex mtu={mtu} store=active | Out-Null
function Convert-PrefixLengthToMask([int]$prefixLength) {{
  $parts = @()
  for ($i = 0; $i -lt 4; $i++) {{
    $remaining = $prefixLength - ($i * 8)
    if ($remaining -ge 8) {{ $parts += 255 }}
    elseif ($remaining -le 0) {{ $parts += 0 }}
    else {{ $parts += [int](256 - [math]::Pow(2, 8 - $remaining)) }}
  }}
  return ($parts -join '.')
}}
foreach ($route in $routes) {{
  if (-not $route) {{ continue }}
  $parts = $route.Split('/')
  $network = $parts[0]
  $prefixLength = if ($parts.Count -gt 1) {{ [int]$parts[1] }} else {{ 32 }}
  $mask = Convert-PrefixLengthToMask $prefixLength
  Remove-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $route -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  & route.exe ADD $network MASK $mask $gateway METRIC 1 IF $ifIndex 2>&1 | Out-Null
  New-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $route -NextHop $gateway -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
}}
if ($dns.Count -gt 0) {{
  & netsh.exe interface ipv4 delete dnsservers $ifIndex all | Out-Null
  foreach ($server in $dns) {{ & netsh.exe interface ipv4 add dnsservers $ifIndex $server validate=no | Out-Null }}
  Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $dns -ErrorAction SilentlyContinue
}}
ipconfig /flushdns | Out-Null
$diagnosticTargets = @($dns | Where-Object {{ $_ -and $_ -notmatch ':' }} | Select-Object -First 1)
if ($diagnosticTargets.Count -eq 0) {{ $diagnosticTargets = @($gateway) }}
$diagnosticRows = foreach ($target in $diagnosticTargets) {{
  Find-NetRoute -RemoteIPAddress $target -ErrorAction SilentlyContinue |
    Select-Object @{{Name='RemoteAddress';Expression={{$target}}}},DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric
}}
$diagnosticRows | ConvertTo-Json -Depth 4
"""
    code, output = run_powershell(ps_script, timeout=30)
    append_log(f"openconnect route fix exit={code}: {output.strip()[:1000]}")
    trace_event("openconnect_route_fix", exit_code=code, gateway=gateway, routes=len(route_prefixes), output=output.strip()[:1000])


def _adapter_ip_rows(ps_script: str) -> list[tuple[str, str]]:
    code, output = run_powershell(ps_script, timeout=4)
    if code != 0:
        return []
    rows: list[tuple[str, str]] = []
    for line in output.splitlines():
        if "\t" not in line:
            continue
        adapter_alias, ip = line.strip().split("\t", 1)
        adapter_alias = adapter_alias.strip()
        ip = ip.strip()
        if adapter_alias and ip:
            rows.append((adapter_alias, ip))
    return rows


def _select_adapter_ipv4(rows: list[tuple[str, str]], expected_ip: str = "") -> tuple[str, str]:
    if expected_ip:
        for adapter_alias, ip in rows:
            if ip == expected_ip:
                return adapter_alias, ip
    for adapter_alias, ip in rows:
        if ip.startswith("10."):
            return adapter_alias, ip
    return rows[0] if rows else ("", "")


def read_adapter_ipv4_with_alias(alias: str, expected_ip: str = "") -> tuple[str, str]:
    if os.name != "nt":
        return "", ""
    if alias:
        alias_literal = alias.replace("'", "''")
        rows = _adapter_ip_rows(
            f"Get-NetIPAddress -InterfaceAlias '{alias_literal}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {{ \"$($_.InterfaceAlias)`t$($_.IPAddress)\" }}"
        )
        selected_alias, ipv4 = _select_adapter_ipv4(rows, expected_ip)
        if ipv4:
            return selected_alias, ipv4
    if expected_ip:
        expected_literal = expected_ip.replace("'", "''")
        rows = _adapter_ip_rows(
            f"Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -eq '{expected_literal}' }} | ForEach-Object {{ \"$($_.InterfaceAlias)`t$($_.IPAddress)\" }}"
        )
        selected_alias, ipv4 = _select_adapter_ipv4(rows, expected_ip)
        if ipv4:
            return selected_alias, ipv4
    return "", ""


def read_adapter_ipv4(alias: str, expected_ip: str = "") -> str:
    return read_adapter_ipv4_with_alias(alias, expected_ip)[1]

def run_openconnect_cookie_backend(
    config: dict,
    svpn_cookie: str,
    vpn_config,
    *,
    should_stop,
    on_ready,
) -> int | None:
    if not config_bool(config, "useOpenconnectBackend", False):
        return None
    script = openconnect_vpnc_script(config)
    if os.name == "nt" and not Path(script).exists():
        append_log(f"OpenConnect backend unavailable; vpnc script not found: {script}")
        trace_event("openconnect_backend_unavailable", reason="script-missing", script=script)
        return None
    exe = openconnect_executable(config)
    alias = openconnect_interface_alias(config)
    interface_arg_alias = openconnect_interface_arg_alias(config)
    server = str(config["server"])
    cmd = [
        exe,
        "--protocol=fortinet",
        "--cookie-on-stdin",
        "--disable-ipv6",
        "--timestamp",
        "--verbose",
    ]
    if interface_arg_alias:
        cmd.append(f"--interface={interface_arg_alias}")
    cmd.append("--script=" + script)
    no_dtls = config_bool(config, "openconnectNoDtls", True)
    if no_dtls:
        cmd.append("--no-dtls")
    dpd_seconds = config_int(config, "openconnectDpdSeconds", 20)
    if dpd_seconds > 0:
        cmd.append(f"--force-dpd={dpd_seconds}")
    reconnect_timeout = config_int(config, "openconnectReconnectTimeoutSeconds", 60)
    if reconnect_timeout > 0:
        cmd.append(f"--reconnect-timeout={reconnect_timeout}")
    extra_args = config.get("openconnectExtraArgs") or []
    if isinstance(extra_args, str):
        extra_args = [item for item in extra_args.split() if item]
    if isinstance(extra_args, list):
        cmd.extend(str(item) for item in extra_args if str(item).strip())
    cmd.append(server)
    append_log("Starting OpenConnect tunnel backend with MyVpn Fortinet cookie.")
    if no_dtls:
        append_log("openconnect option: --no-dtls enabled to match FortiClient DTLS preference off and avoid DTLS fallback delay.")
    if dpd_seconds > 0:
        append_log(f"openconnect option: --force-dpd={dpd_seconds} for tunnel keepalive/dead-peer detection.")
    if interface_arg_alias:
        append_log(f"openconnect option: --interface={interface_arg_alias}.")
    else:
        append_log("openconnect option: automatic tunnel adapter selection; default MyVpnClient alias is not forced.")
    trace_event("openconnect_start", exe=exe, interface=alias, interfaceArg=interface_arg_alias or "auto", script=script, noDtls=no_dtls, dpdSeconds=dpd_seconds, reconnectTimeoutSeconds=reconnect_timeout)
    openconnect_output_tail: list[str] = []
    adapter_alias_lock = threading.Lock()
    effective_adapter_alias = interface_arg_alias
    session_expiry_at: datetime | None = None
    session_expiry_warning_sent = False
    session_expiry_expired_sent = False

    def openconnect_is_running() -> bool:
        try:
            return proc.poll() is None
        except NameError:
            return False

    def session_expiry_watch(expiry_at: datetime) -> None:
        nonlocal session_expiry_warning_sent, session_expiry_expired_sent
        warning_minutes = max(0.0, config_float(config, "notifySessionExpiryWarningMinutes", 10.0))
        warning_at = expiry_at - timedelta(minutes=warning_minutes)
        wait_seconds = (warning_at - datetime.now()).total_seconds()
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        if warning_minutes > 0 and openconnect_is_running() and not session_expiry_warning_sent:
            session_expiry_warning_sent = log_session_expiry_event(config, expiry_at, "approaching", "timer") or True
        wait_seconds = (expiry_at - datetime.now()).total_seconds()
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        if openconnect_is_running() and not session_expiry_expired_sent:
            session_expiry_expired_sent = log_session_expiry_event(config, expiry_at, "expired", "timer") or True

    def track_session_expiry_line(text: str) -> None:
        nonlocal session_expiry_at, session_expiry_expired_sent
        expiry_at = parse_openconnect_session_expiry(text)
        if expiry_at is not None:
            session_expiry_at = expiry_at
            trace_event("openconnect_session_expiry_detected", expiresAt=expiry_at.strftime("%Y-%m-%d %H:%M:%S"))
            threading.Thread(target=session_expiry_watch, args=(expiry_at,), name="openconnect-session-expiry-watch", daemon=True).start()
            return
        if "Send PPP echo request as DPD" in text and session_expiry_at is not None and datetime.now() >= session_expiry_at and not session_expiry_expired_sent:
            session_expiry_expired_sent = log_session_expiry_event(config, session_expiry_at, "expired", "dpd-after-expiry") or True

    def set_effective_adapter_alias(detected_alias: str, source: str) -> None:
        nonlocal effective_adapter_alias
        detected_alias = detected_alias.strip()
        if not detected_alias:
            return
        with adapter_alias_lock:
            if effective_adapter_alias == detected_alias:
                return
            effective_adapter_alias = detected_alias
        trace_event("openconnect_adapter_alias_detected", interface=detected_alias, source=source)

    def get_effective_adapter_alias() -> str:
        with adapter_alias_lock:
            return effective_adapter_alias

    def record_openconnect_line(line: str) -> None:
        text = line.rstrip()
        if not text:
            return
        openconnect_output_tail.append(text)
        del openconnect_output_tail[:-40]
        append_log("openconnect: " + text)
        trace_event("openconnect_output", line=text[:1000])
        track_session_expiry_line(text)
        detected_alias = parse_openconnect_adapter_alias(text)
        if detected_alias:
            set_effective_adapter_alias(detected_alias, "openconnect-output")

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=CREATE_NO_WINDOW,
            cwd=str(Path(exe).resolve().parent) if exe != "openconnect" else None,
        )
    except OSError as exc:
        append_log(f"OpenConnect backend could not start: {exc}")
        trace_event("openconnect_start_failed", error=str(exc))
        return None

    start_owner_watch_thread(proc, config)

    configured_ip = ""
    ready_sent = False
    ready_lock = threading.Lock()
    expected_ip = ""
    if vpn_config and getattr(vpn_config, "assigned_ipv4", None):
        expected_ip = str(vpn_config.assigned_ipv4[0])

    def mark_openconnect_ready(ipv4: str, source: str, adapter_alias: str = "") -> None:
        nonlocal configured_ip, ready_sent
        if not ipv4:
            return
        with ready_lock:
            if ready_sent:
                return
            configured_ip = ipv4
            ready_sent = True
        runtime_alias = adapter_alias or get_effective_adapter_alias() or alias
        runtime_config = config_with_openconnect_interface_alias(config, runtime_alias)
        routes = effective_vpn_routes(config, vpn_config)
        dns = vpn_config.dns if vpn_config else []
        append_log(f"OpenConnect network ready via {source}: IPv4={ipv4}; interface={runtime_alias}")
        trace_event("openconnect_ready", source=source, ipv4=ipv4, interface=runtime_alias)
        remember_myvpn_routes(runtime_config, ipv4, routes, dns)
        apply_openconnect_route_fix(runtime_config, ipv4, routes, dns)
        on_ready(ipv4)

    def adapter_ready_watch() -> None:
        deadline = time.monotonic() + float(config.get("openconnectAdapterReadyTimeoutSeconds") or 35)
        while proc.poll() is None and time.monotonic() < deadline:
            if should_stop():
                return
            detected_alias, ipv4 = read_adapter_ipv4_with_alias(get_effective_adapter_alias(), expected_ip)
            if ipv4:
                if detected_alias:
                    set_effective_adapter_alias(detected_alias, "adapter-ip")
                mark_openconnect_ready(ipv4, "adapter-ip", detected_alias)
                return
            time.sleep(float(config.get("openconnectAdapterReadyPollSeconds") or 0.5))
        trace_event("openconnect_adapter_ready_timeout", expected=expected_ip, interface=get_effective_adapter_alias() or "auto")

    threading.Thread(target=adapter_ready_watch, name="openconnect-adapter-ready", daemon=True).start()
    try:
        assert proc.stdin is not None
        proc.stdin.write("SVPNCOOKIE=" + svpn_cookie + "\n")
        proc.stdin.close()
        while proc.poll() is None:
            line = proc.stdout.readline() if proc.stdout is not None else ""
            if line:
                record_openconnect_line(line)
            else:
                time.sleep(0.2)
            if should_stop():
                append_log("Stopping OpenConnect backend because MyVpn state requested stop.")
                proc.terminate()
                break
        if proc.stdout is not None:
            for remaining in proc.stdout.readlines():
                record_openconnect_line(remaining)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        exit_code = int(proc.returncode or 0)
        trace_event("openconnect_exit", exit_code=exit_code, configured=bool(configured_ip), outputTail=openconnect_output_tail)
        if not configured_ip and exit_code == 0:
            return 2
        return exit_code
    finally:
        if proc.poll() is None:
            proc.terminate()

def connect_myvpn_once(config: dict) -> int:
    normalize_config_keys(config)
    require_admin_for_windows()
    STATE_DIR.mkdir(exist_ok=True)
    claimed, claim_message = claim_vpn_pid()
    if not claimed:
        append_log("myvpn_tunnel cannot start: " + claim_message)
        write_myvpn_state(config, "tunnel-open-failed", claim_message)
        return 2
    start_trace()
    MYVPN_STATE_FILE.unlink(missing_ok=True)
    write_myvpn_state(config, "authenticating", "Waiting for Fortinet authentication and MFA.", mfaStatus="idle")
    password = config.get("password") or load_dpapi_password()
    if not password:
        message = "Saved VPN password is unavailable; open Settings and save the password again."
        append_log("myvpn_tunnel cannot start: " + message)
        trace_event("password_missing")
        write_myvpn_state(config, "auth-failed", message)
        PID_FILE.unlink(missing_ok=True)
        return 2

    username = config.get("username")
    if not username:
        if sys.stdin.isatty():
            username = input("VPN username: ")
        else:
            message = "VPN username is missing; open Settings and save the profile username."
            append_log("myvpn_tunnel cannot start: " + message)
            trace_event("username_missing")
            write_myvpn_state(config, "auth-failed", message)
            PID_FILE.unlink(missing_ok=True)
            return 2
    realm = config.get("authgroup") or config.get("realm") or ""
    mfa_response = config.get("mfaResponse") or None
    blank_mfa = bool(config.get("autoPushMfa", True)) and not mfa_response

    append_log(f"\n--- myvpn connect {now_text()} ---")
    append_log("Starting integrated myvpn_tunnel TLS tunnel engine.")
    append_log("This backend opens the Fortinet TLS tunnel stream and runs an experimental PPP/TAP engine.")
    network_capture_thread = start_network_transaction_capture(config)

    client = FortinetClient(
        base_url_from_server(config["server"]),
        verify_tls=bool(config.get("verifyTls", True)),
        user_agent=config.get("userAgent") or "Mozilla/5.0 SV1",
        timeout=config_float(config, "timeoutSeconds", 90),
    )
    retry_count = config_int(config, "authRetryCount", 0)
    result = None
    for attempt in range(retry_count + 1):
        attempt_label = attempt + 1
        append_log(f"myvpn_tunnel login attempt {attempt_label}/{retry_count + 1} started; approve FortiToken push if prompted.")
        trace_event("login_start", attempt=attempt_label, blank_mfa=blank_mfa, max_challenges=int(config.get("mfaBlankResponses") or 3))
        def live_login_event(event: str, **fields) -> None:
            if event == "login_http":
                cookies = fields.get("cookies") or []
                cookie_text = ", ".join(cookies) if cookies else "(none)"
                append_log(
                    "myvpn_tunnel auth http: "
                    f"{fields.get('method')} {fields.get('path')} -> HTTP {fields.get('status')}; "
                    f"request={fields.get('request', 'probe')}; response={fields.get('response')}; cookies={cookie_text}"
                )
            message = fields.get("message")
            if message:
                text = str(message)
                append_log("myvpn_tunnel note: " + text)
                lowered = text.lower()
                if "tokeninfo" in lowered and "mfa" in lowered:
                    write_myvpn_state(config, "authenticating", "FortiToken/MFA push sent; waiting for mobile approval.", mfaStatus="requested")
                elif "mfa logincheck" in lowered:
                    write_myvpn_state(config, "authenticating", "MFA logincheck in progress; waiting for mobile approval.", mfaStatus="requested")
            trace_event(event, **fields)

        try:
            result = client.login(
                username,
                password,
                realm=realm,
                mfa_code=mfa_response,
                blank_mfa=blank_mfa,
                max_challenges=int(config.get("mfaBlankResponses") or 3),
                fetch_config=True,
                show_cookie_value=True,
                on_event=live_login_event,
            )
        except TimeoutError as exc:
            append_log(f"myvpn_tunnel login timed out while waiting for FortiToken/server response: {exc}")
            trace_event("login_timeout", attempt=attempt_label, error=str(exc))
            if attempt >= retry_count:
                write_myvpn_state(config, "auth-timeout", "Fortinet/MFA login timed out before a VPN cookie was issued.", mfaStatus="failed")
                PID_FILE.unlink(missing_ok=True)
                return 2
            continue
        if result.ok and result.cookie_value:
            break
        if attempt < retry_count and blank_mfa:
            reason = classify_myvpn_auth_failure(result)
            append_log(f"myvpn_tunnel auth attempt {attempt_label} did not produce a cookie; retrying: {reason}")
            trace_event("login_retry", attempt=attempt_label, reason=reason)
            continue
        break

    assert result is not None

    append_log(f"myvpn_tunnel status: {result.status}")
    append_log("myvpn_tunnel cookies: " + (", ".join(result.cookie_names) or "(none)"))
    trace_event("login_result", status=result.status, cookies=result.cookie_names)
    for line in summarize_config(result.config):
        append_log("myvpn_tunnel " + line)

    if result.ok and result.cookie_value:
        write_myvpn_state(config, "authenticated", "VPN cookie received; TLS tunnel stream starting.", mfaStatus="accepted")
        vpn_config = result.config

        network_check_failed = False
        network_check_complete = False
        network_check_started = False
        stop_after_network_check = bool(config.get("diagnosticStopAfterNetworkCheck", False))
        network_check_failure_terminates = bool(config.get("networkCheckFailureTerminates", stop_after_network_check))
        network_check_lock = threading.Lock()

        def myvpn_should_stop() -> bool:
            with network_check_lock:
                failed = network_check_failed
                complete = network_check_complete
            return owner_is_gone() or (network_check_failure_terminates and failed) or (stop_after_network_check and complete)

        def mark_myvpn_network_ready(ipv4: str) -> None:
            nonlocal network_check_failed, network_check_complete, network_check_started
            remember_myvpn_routes(
                config,
                ipv4,
                effective_vpn_routes(config, vpn_config),
                (vpn_config.dns if vpn_config else []),
            )
            with network_check_lock:
                if network_check_started:
                    return
                network_check_started = True
            with network_check_lock:
                network_check_complete = True
            write_myvpn_state(config, "network-ready", "VPN tunnel is up.", ipv4=ipv4, networkCheck="disabled")
            trace_event("network_check_skipped", reason="host checks removed from MyVpnClient")
            return

        def mark_myvpn_phase(phase: str, detail: str = "") -> None:
            with network_check_lock:
                stopping_for_network_check = network_check_failed or (stop_after_network_check and network_check_complete)
            if stopping_for_network_check and phase == "terminating":
                trace_event("ppp_phase", phase=phase, detail=detail)
                return
            state = phase if phase in {"negotiation-timeout", "tunnel-stalled"} else f"ppp-{phase}"
            note = detail or f"PPP phase {phase}."
            write_myvpn_state(config, state, note)
            trace_event("ppp_phase", phase=phase, detail=detail)

        def mark_myvpn_stats(stats: dict) -> None:
            try:
                current = json.loads(MYVPN_STATE_FILE.read_text(encoding="utf-8")) if MYVPN_STATE_FILE.exists() else {}
            except (OSError, json.JSONDecodeError):
                current = {}
            current["stats"] = stats
            current["time"] = now_text()
            MYVPN_STATE_FILE.write_text(json.dumps(current, indent=2), encoding="utf-8")
            trace_event("ppp_stats", **stats)

        def mark_myvpn_packet(direction: str, summary: dict) -> None:
            trace_packets = config_bool(config, "tracePackets", False)
            trace_dns_packets = config_bool(config, "traceDnsPackets", trace_packets)
            if "dnsId" in summary:
                if not trace_dns_packets:
                    return
                event = "dns_packet"
            elif not trace_packets:
                return
            elif summary.get("flowKind") == "tcp" or summary.get("ipProto") == 6:
                event = "tcp_packet"
            else:
                event = "flow_packet"
            trace_event(event, direction=direction, **summary)

        negotiation_timeout = config_float(config, "pppNegotiationTimeoutSeconds", config_float(config, "timeoutSeconds", 90))
        idle_timeout = config_float(config, "tunnelIdleTimeoutSeconds", 0)
        terminate_grace = config_float(config, "terminateGraceSeconds", 2)

        if config_bool(config, "useOpenconnectBackend", False):
            openconnect_started = False
            try:
                openconnect_exit = run_openconnect_cookie_backend(
                    config,
                    result.cookie_value,
                    vpn_config,
                    should_stop=myvpn_should_stop,
                    on_ready=mark_myvpn_network_ready,
                )
                openconnect_started = openconnect_exit is not None
                if openconnect_started:
                    with network_check_lock:
                        failed_after_openconnect = network_check_failed
                        completed_after_openconnect = network_check_complete
                    if failed_after_openconnect:
                        openconnect_exit = 4
                    elif stop_after_network_check and completed_after_openconnect:
                        openconnect_exit = 0
                    openconnect_exit_code = int(openconnect_exit)
                    if openconnect_exit_code != 0 and not failed_after_openconnect:
                        if not completed_after_openconnect:
                            write_myvpn_state(config, "tunnel-open-failed", f"OpenConnect backend exited before VPN network was ready, exit code {openconnect_exit_code}.")
                        else:
                            write_myvpn_state(config, "tunnel-lost", f"OpenConnect backend exited after VPN network was ready, exit code {openconnect_exit_code}.")
                    trace_event("tunnel_exit", backend="openconnect", exit_code=openconnect_exit_code)
                    return openconnect_exit_code
            finally:
                if openconnect_started:
                    cleanup_windows_network_state(config, reason="openconnect exit")
                    PID_FILE.unlink(missing_ok=True)
                    with network_check_lock:
                        preserve_network_state = network_check_failed or (stop_after_network_check and network_check_complete)
                    if preserve_network_state:
                        pass
                    elif not is_myvpn_terminal_state(current_myvpn_state_name()):
                        MYVPN_STATE_FILE.unlink(missing_ok=True)

        if config_bool(config, "preferDtls", False) and config_bool(config, "enableExperimentalDtls", False):
            dtls_transport = None
            dtls_started = False
            tap = None
            try:
                append_log("myvpn_tunnel authenticated; attempting Fortinet DTLS tunnel.")
                trace_event("dtls_open_start")
                dtls_transport = FortinetDtlsTransport(
                    base_url_from_server(config["server"]),
                    result.cookie_value,
                    verify_tls=bool(config.get("verifyTls", True)),
                    timeout=config_float(config, "timeoutSeconds", 90),
                    log=append_log,
                )
                dtls_sock = dtls_transport.open()
                dtls_started = True
                write_myvpn_state(config, "dtls-tunnel-running", "DTLS tunnel is open with experimental PPP packet-adapter engine.")
                tap = open_myvpn_packet_adapter(config)
                exit_code = FortinetPppEngine(
                    dtls_sock,
                    tap=tap,
                    log=append_log,
                    routes=effective_vpn_routes(config, vpn_config),
                    dns=(vpn_config.dns if vpn_config else []),
                    metric=int(config.get("tapInterfaceMetric") or 1),
                    on_ready=mark_myvpn_network_ready,
                    on_phase=mark_myvpn_phase,
                    on_stats=mark_myvpn_stats,
                    on_packet=mark_myvpn_packet,
                    trace_flows=config_bool(config, "tracePackets", False),
                    fast_data_path=config_bool(config, "fastDataPath", True),
                    negotiation_timeout=negotiation_timeout,
                    idle_timeout=idle_timeout,
                    terminate_grace=terminate_grace,
                ).run(should_stop=myvpn_should_stop)
                with network_check_lock:
                    failed_after_dtls = network_check_failed
                if failed_after_dtls:
                    trace_event("tunnel_exit", exit_code=4)
                    return 4
                if exit_code != 0:
                    trace_event("dtls_ppp_failed_fallback", exit_code=exit_code)
                    raise DtlsUnavailable(f"DTLS PPP engine exited with code {exit_code}; falling back to TLS.")
                if exit_code == 3:
                    write_myvpn_state(config, "negotiation-timeout", "PPP negotiation timed out before the tunnel became network-ready.")
                elif exit_code == 4:
                    write_myvpn_state(config, "tunnel-stalled", "PPP tunnel stalled after becoming network-ready.")
                return exit_code
            except DtlsUnavailable as exc:
                append_log(str(exc))
                append_log("myvpn_tunnel falling back to Fortinet TLS tunnel.")
                trace_event("dtls_unavailable", error=str(exc))
            finally:
                if tap:
                    tap.close()
                if dtls_started:
                    cleanup_windows_network_state(config, reason="myvpn_tunnel DTLS exit")
                if dtls_transport:
                    dtls_transport.close()
                if dtls_started:
                    PID_FILE.unlink(missing_ok=True)
                    if not is_myvpn_terminal_state(current_myvpn_state_name()):
                        MYVPN_STATE_FILE.unlink(missing_ok=True)

        append_log("myvpn_tunnel authenticated; opening /remote/sslvpn-tunnel.")
        trace_event("tls_tunnel_open_start", path="/remote/sslvpn-tunnel")
        tunnel = FortinetTlsTunnel(
            base_url_from_server(config["server"]),
            result.cookie_value,
            verify_tls=bool(config.get("verifyTls", True)),
            user_agent=config.get("userAgent") or "Mozilla/5.0 SV1",
            timeout=config_float(config, "timeoutSeconds", 90),
        )
        try:
            try:
                open_result = tunnel.open()
            except TimeoutError as exc:
                message = "Tunnel endpoint did not send an initial response before the read timeout."
                append_log(f"myvpn_tunnel tunnel endpoint timed out: {exc}")
                trace_event("tls_tunnel_open_timeout", error=str(exc))
                write_myvpn_state(config, "tunnel-open-failed", message)
                return 2
            except OSError as exc:
                message = f"Tunnel endpoint could not be opened: {exc}"
                append_log(f"myvpn_tunnel tunnel endpoint open failed: {exc}")
                trace_event("tls_tunnel_open_failed", error=str(exc))
                write_myvpn_state(config, "tunnel-open-failed", message)
                return 2
            append_log(f"myvpn_tunnel tunnel endpoint opened: {open_result.reason}")
            trace_event("tls_tunnel_opened", status_code=open_result.status_code, reason=open_result.reason)
            if open_result.status_code and (open_result.status_code < 200 or open_result.status_code >= 300):
                write_myvpn_state(config, "tunnel-open-failed", f"Tunnel endpoint returned HTTP {open_result.status_code}.")
                return 2
            write_myvpn_state(config, "tls-tunnel-running", "TLS tunnel stream is open with experimental PPP/TAP engine.")
            tap = open_myvpn_packet_adapter(config)
            try:
                exit_code = tunnel.run(
                    should_stop=myvpn_should_stop,
                    log=append_log,
                    tap=tap,
                    routes=effective_vpn_routes(config, vpn_config),
                    dns=(vpn_config.dns if vpn_config else []),
                    metric=int(config.get("tapInterfaceMetric") or 1),
                    on_ready=mark_myvpn_network_ready,
                    on_phase=mark_myvpn_phase,
                    on_stats=mark_myvpn_stats,
                    on_packet=mark_myvpn_packet,
                    trace_flows=config_bool(config, "tracePackets", False),
                    fast_data_path=config_bool(config, "fastDataPath", True),
                    negotiation_timeout=negotiation_timeout,
                    idle_timeout=idle_timeout,
                    terminate_grace=terminate_grace,
                )
                with network_check_lock:
                    failed_after_tls = network_check_failed
                if failed_after_tls:
                    exit_code = 4
                trace_event("tunnel_exit", exit_code=exit_code)
                if exit_code == 3:
                    write_myvpn_state(config, "negotiation-timeout", "PPP negotiation timed out before the tunnel became network-ready.")
                elif exit_code == 4 and not failed_after_tls:
                    write_myvpn_state(config, "tunnel-stalled", "PPP tunnel stalled after becoming network-ready.")
                return exit_code
            finally:
                if tap:
                    tap.close()
        finally:
            tunnel.close()
            cleanup_windows_network_state(config, reason="myvpn_tunnel TLS exit")
            PID_FILE.unlink(missing_ok=True)
            with network_check_lock:
                preserve_network_state = network_check_failed or (stop_after_network_check and network_check_complete)
            if preserve_network_state:
                pass
            elif not is_myvpn_terminal_state(current_myvpn_state_name()):
                MYVPN_STATE_FILE.unlink(missing_ok=True)

    reason = classify_myvpn_auth_failure(result)
    write_myvpn_state(config, "auth-failed", reason, mfaStatus="failed")
    append_log(f"myvpn_tunnel failed: {result.status}; {reason}")
    print(f"myvpn_tunnel failed: {result.status}")
    PID_FILE.unlink(missing_ok=True)
    return 2


def open_myvpn_packet_adapter(config: dict):
    if not config_bool(config, "enableTap", True):
        return None
    if not packet_adapter_available():
        append_log("myvpn_tunnel packet adapter support is unavailable in this Python runtime.")
        return None
    kind = config_value(config, "adapterKind", "auto") or "auto"
    alias = config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
    if config_bool(config, "lazyPacketAdapter", True):
        append_log(f"myvpn_tunnel deferring packet adapter open until PPP network-ready: {alias} ({kind}).")
        trace_event("packet_adapter_open_deferred", adapterKind=kind, interface=alias)
        return LazyPacketAdapter(str(kind), str(alias))
    return open_packet_adapter(kind, alias, log=append_log)


def connect_interactive(config_path: Path) -> int:
    print("Interactive mode now uses integrated myvpn_tunnel.")
    return connect_myvpn(load_config(config_path))


def disconnect(config_path: Path = DEFAULT_CONFIG) -> int:
    MYVPN_STATE_FILE.unlink(missing_ok=True)
    try:
        config = load_config(config_path)
    except SystemExit:
        config = {}
    pid = read_pid()
    if not pid:
        cleanup_windows_network_state(config, reason="disconnect with no active PID")
        print("No PID file found; nothing to disconnect.")
        return 0
    if not is_running(pid):
        print(f"PID {pid} is not running; cleaning state.")
        cleanup_windows_network_state(config, reason="stale PID")
        PID_FILE.unlink(missing_ok=True)
        return 0

    print(f"Stopping VPN PID {pid}...")
    terminate_process_tree(pid)
    cleanup_windows_network_state(config, reason="disconnect")
    PID_FILE.unlink(missing_ok=True)
    return 0


def reset_network(config_path: Path = DEFAULT_CONFIG) -> int:
    try:
        config = load_config(config_path)
    except SystemExit:
        config = {}
    pid = read_pid()
    if pid and is_running(pid):
        print(f"Stopping VPN PID {pid} before reset...")
        terminate_process_tree(pid)
    cleanup_windows_network_state(config, reason="manual reset")
    PID_FILE.unlink(missing_ok=True)
    OWNER_PID_FILE.unlink(missing_ok=True)
    MYVPN_STATE_FILE.unlink(missing_ok=True)
    MYVPN_ROUTES_FILE.unlink(missing_ok=True)
    print("VPN network state reset complete.")
    return 0


def status(config_path: Path = DEFAULT_CONFIG) -> int:
    try:
        config = load_config(config_path)
    except SystemExit:
        config = {}
    pid = read_pid()
    if pid and is_running(pid):
        if not MYVPN_STATE_FILE.exists():
            print(f"myvpn_tunnel authenticating PID {pid}: waiting for Fortinet/MFA response.")
            return 0
        try:
            state = json.loads(MYVPN_STATE_FILE.read_text(encoding="utf-8"))
            print(
                "myvpn_tunnel "
                f"{state.get('status', 'running')} PID {pid}: {state.get('note', '')}"
            )
            return 0
        except (OSError, json.JSONDecodeError):
            print(f"myvpn_tunnel PID {pid} is running.")
            return 0
    if MYVPN_STATE_FILE.exists():
        try:
            state = json.loads(MYVPN_STATE_FILE.read_text(encoding="utf-8"))
            state_name = state.get("status", "stopped")
            note = state.get("note", "")
            print(f"myvpn_tunnel {state_name}: {note}")
            if state_name in {"auth-failed", "auth-timeout", "tunnel-open-failed"}:
                return 1
        except (OSError, json.JSONDecodeError):
            pass
    if pid:
        PID_FILE.unlink(missing_ok=True)
    MYVPN_STATE_FILE.unlink(missing_ok=True)
    print("No tunnel process is active.")
    return 1


def status_payload(config_path: Path = DEFAULT_CONFIG) -> dict:
    try:
        config = load_config(config_path)
    except SystemExit as exc:
        return {
            "backend": BACKEND_MYVPN,
            "state": "disconnected",
            "detail": str(exc),
            "pid": None,
            "pidRunning": False,
        }

    backend = backend_name(config)
    pid = read_pid()
    pid_running = bool(pid and is_running(pid))
    payload = {
        "backend": backend,
        "state": "disconnected",
        "detail": "Not running.",
        "pid": pid,
        "pidRunning": pid_running,
        "time": now_text(),
    }

    if MYVPN_STATE_FILE.exists():
        try:
            state = json.loads(MYVPN_STATE_FILE.read_text(encoding="utf-8"))
            payload.update(
                {
                    "state": state.get("status", "running") if pid_running else state.get("status", "stopped"),
                    "detail": state.get("note", ""),
                    "ipv4": state.get("ipv4", ""),
                    "server": state.get("server", config.get("server", "")),
                    "stats": state.get("stats", {}),
                    "mfaStatus": state.get("mfaStatus", ""),
                    "connectedAt": (
                        state.get("connectedAt") or state.get("time", "")
                        if state.get("status") == "network-ready"
                        else ""
                    ),
                }
            )
        except (OSError, json.JSONDecodeError):
            payload.update({"state": "running" if pid_running else "disconnected", "detail": "Tunnel state is unreadable."})
    elif pid_running:
        payload.update({"state": "authenticating", "detail": "Waiting for Fortinet/MFA response."})
    else:
        payload.update({"state": "disconnected", "detail": "No tunnel process is active."})

    payload["connected"] = payload["state"] == "network-ready"
    payload["connecting"] = payload["state"] in {
        "authenticating",
        "authenticated",
        "tls-tunnel-running",
        "dtls-tunnel-running",
        "running",
        "ppp-lcp-start",
        "ppp-lcp-opened",
        "ppp-ipcp-start",
        "ppp-terminating",
        "reconnect-wait",
    }
    payload["terminalFailure"] = payload["state"] in {
        "auth-failed",
        "auth-timeout",
        "tunnel-open-failed",
        "tunnel-lost",
        "negotiation-timeout",
        "tunnel-stalled",
    }
    payload.update(state_metadata(str(payload["state"]), str(payload.get("detail") or "")))
    return payload


def status_json(config_path: Path = DEFAULT_CONFIG) -> int:
    print(json.dumps(status_payload(config_path), indent=2))
    payload = status_payload(config_path)
    return 0 if payload.get("pidRunning") or payload.get("connected") else 1


def logs(lines: int) -> int:
    log_file = readable_log_file()
    if not log_file.exists():
        print(f"No log file yet: {LOG_FILE}")
        return 1
    content = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in content[-lines:]:
        print(line)
    return 0


def run_text(command: list[str], timeout: int = 12) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return result.returncode, (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except OSError as exc:
        return 127, str(exc)


def run_powershell(command: str, timeout: int = 12) -> tuple[int, str]:
    return run_text(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], timeout=timeout)


def check_item(name: str, ok: bool, detail: str, action: str = "") -> dict:
    return {
        "name": name,
        "ok": bool(ok),
        "detail": detail,
        "action": action,
    }

def required_preflight_paths(app_dir: Path = APP_DIR) -> list[tuple[str, Path]]:
    return [
        ("myvpnclient_bridge.py", app_dir / "myvpnclient_bridge.py"),
        ("connect-admin.ps1", app_dir / "connect-admin.ps1"),
        ("task-connect.ps1", app_dir / "task-connect.ps1"),
        ("task-disconnect.ps1", app_dir / "task-disconnect.ps1"),
        ("run-helper-task.ps1", app_dir / "run-helper-task.ps1"),
        ("backend/myvpn_tunnel", app_dir / "backend" / "myvpn_tunnel"),
    ]


def preflight_payload(config_path: Path = DEFAULT_CONFIG) -> dict:
    checks = []
    config: dict = {}
    try:
        config = load_config(config_path)
        checks.append(check_item("config", True, f"Loaded {config_path}"))
    except SystemExit as exc:
        checks.append(check_item("config", False, str(exc), "Copy config.example.json to config.json and fill required fields."))
        return {"ok": False, "time": now_text(), "checks": checks}

    checks.append(check_item("server", bool(config.get("server")), config.get("server") or "Missing server.", "Set VPN server in Settings."))
    checks.append(check_item("username", bool(config.get("username")), "Username is set." if config.get("username") else "Missing username.", "Set username in Settings."))
    has_password = bool(config.get("password") or load_dpapi_password())
    checks.append(check_item("password", has_password, "Password is available." if has_password else "Saved password is unavailable.", "Save password again in Settings."))
    helper_task_available = False
    if os.name == "nt":
        task_code, _ = run_text(["schtasks.exe", "/Query", "/TN", "MyVpnClient-Connect"], timeout=8)
        helper_task_available = task_code == 0
    checks.append(check_item(
        "elevation",
        is_admin() or os.name != "nt" or helper_task_available,
        "Administrator privileges available." if is_admin() else "Installed helper task is available." if helper_task_available else "Not running as Administrator.",
        "Run MyVpnClient as Administrator."))

    for label, path in required_preflight_paths(APP_DIR):
        checks.append(check_item(f"file:{label}", path.exists(), str(path), "Reinstall or rebuild MyVpnClient."))

    use_openconnect_backend = config_bool(config, "useOpenconnectBackend", True)
    adapter_required = config_bool(config, "enableTap", True) and not use_openconnect_backend
    adapter_support = packet_adapter_available()
    checks.append(check_item(
        "packet-adapter-module",
        adapter_support or not adapter_required,
        "Packet adapter module is importable." if adapter_support else "Packet adapter module is unavailable; ignored while OpenConnect backend is enabled.",
        "Check Windows/TAP/Wintun dependencies only if using the native tunnel."))
    if use_openconnect_backend:
        exe = openconnect_executable(config)
        script = openconnect_vpnc_script(config)
        exe_ok = exe == "openconnect" or Path(exe).exists()
        checks.append(check_item("openconnect-exe", exe_ok, exe if exe_ok else f"OpenConnect executable not found: {exe}", "Reinstall MyVpnClient or set openconnectPath."))
        script_ok = Path(script).exists()
        checks.append(check_item("openconnect-script", script_ok, script if script_ok else f"OpenConnect script not found: {script}", "Reinstall MyVpnClient or set openconnectScript."))
        alias = openconnect_interface_alias(config)
        checks.append(check_item("openconnect-interface", bool(alias), alias or "Missing OpenConnect adapter alias.", "Set openconnectInterfaceAlias in Settings."))
    if os.name == "nt" and adapter_required:
        alias = config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
        alias_escaped = str(alias).replace("'", "''")
        code, output = run_powershell(
            f"Get-NetAdapter -IncludeHidden -Name '{alias_escaped}' -ErrorAction SilentlyContinue | "
            "Select-Object Name,Status,InterfaceDescription | ConvertTo-Json -Depth 3",
            timeout=8,
        )
        checks.append(check_item("adapter", code == 0 and bool(output.strip()), output.strip() or f"Adapter not found: {alias}", "Install or select a TAP/Wintun adapter for the native tunnel."))

    if config_bool(config, "preferDtls", False):
        try:
            from myvpn_tunnel.dtls import find_libcrypto, find_libssl

            libssl = find_libssl()
            checks.append(check_item("dtls-libssl", True, str(libssl)))
        except Exception as exc:
            checks.append(check_item("dtls-libssl", False, str(exc), "Disable DTLS or install libssl-3.dll."))
        try:
            libcrypto = find_libcrypto()
            checks.append(check_item("dtls-libcrypto", True, str(libcrypto)))
        except Exception as exc:
            checks.append(check_item("dtls-libcrypto", False, str(exc), "Disable DTLS or install libcrypto-3.dll."))

    if config.get("server"):
        host = base_url_from_server(str(config["server"])).split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        code, output = run_text(["powershell.exe", "-NoProfile", "-Command", f"Resolve-DnsName '{host.replace("'", "''")}' -ErrorAction SilentlyContinue | Select-Object -First 1 | ConvertTo-Json -Depth 3"], timeout=8)
        checks.append(check_item("dns", code == 0 and bool(output.strip()), output.strip() or f"Unable to resolve {host}.", "Check DNS/VPN server hostname."))

    ok = all(item["ok"] for item in checks)
    return {
        "ok": ok,
        "time": now_text(),
        "summary": "Preflight passed." if ok else "Preflight found issues before connect.",
        "checks": checks,
    }


def preflight_json(config_path: Path = DEFAULT_CONFIG) -> int:
    payload = preflight_payload(config_path)
    print(json.dumps(payload, indent=2))
    return 0 if payload.get("ok") else 1


def sandbox_check_payload(config_path: Path = DEFAULT_CONFIG) -> dict:
    try:
        config = load_config(config_path)
    except SystemExit as exc:
        config = {"server": "sandbox.invalid", "username": "sandbox-user"}
        config_error = str(exc)
    else:
        config_error = ""

    transitions = [
        state_metadata("authenticating", "Sandbox: signing in without network access."),
        state_metadata("authenticated", "Sandbox: VPN cookie simulated."),
        state_metadata("tls-tunnel-running", "Sandbox: tunnel stream simulated."),
        state_metadata("ppp-lcp-start", "Sandbox: PPP LCP start simulated."),
        state_metadata("ppp-lcp-opened", "Sandbox: PPP LCP opened."),
        state_metadata("ppp-ipcp-start", "Sandbox: PPP IPCP start simulated."),
        state_metadata("network-ready", "Sandbox: network-ready simulated without adapter changes."),
    ]
    return {
        "ok": True,
        "time": now_text(),
        "mode": "offline-sandbox",
        "server": config.get("server", "sandbox.invalid"),
        "configWarning": config_error,
        "changesNetwork": False,
        "requiresAdmin": False,
        "transitions": transitions,
        "summary": "Offline sandbox state model completed without touching credentials, adapters, routes, or network.",
    }


def sandbox_check_json(config_path: Path = DEFAULT_CONFIG) -> int:
    print(json.dumps(sandbox_check_payload(config_path), indent=2))
    return 0


def redact_diagnostic_text(text: str) -> str:
    return SENSITIVE_TEXT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text or "")


def powershell_capture(name: str, command: str, timeout: int = 20) -> dict:
    code, output = run_powershell(command, timeout=timeout)
    return {
        "name": name,
        "ok": code == 0,
        "exitCode": code,
        "output": redact_diagnostic_text(output.strip()),
    }


def trace_tail(limit: int = 240, path: Path | None = None) -> list[dict]:
    trace_path = path or CURRENT_TRACE_FILE
    if not trace_path.exists():
        return []
    try:
        lines = trace_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    events = []
    for line in lines[-limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"raw": line})
    return events

def diagnostic_hosts(config: dict) -> list[str]:
    return []

def network_diagnostic_payload(config: dict) -> dict:
    alias = config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
    hosts = diagnostic_hosts(config)
    vpn_dns = config.get("vpnDnsServers") or DEFAULT_VPN_DNS
    try:
        tracked = json.loads(MYVPN_ROUTES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        tracked = {}
    if not vpn_dns:
        vpn_dns = tracked.get("dns") or []
    if not vpn_dns:
        for event in reversed(trace_tail()):
            if event.get("event") == "network_routes_tracked" and event.get("dns"):
                vpn_dns = event.get("dns")
                break
    if isinstance(vpn_dns, str):
        vpn_dns = [item.strip() for item in vpn_dns.split(",") if item.strip()]

    escaped_alias = str(alias).replace("'", "''")
    captures = [
        powershell_capture(
            "adapters",
            "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -match 'Local Area Connection|VPN' -or $_.InterfaceDescription -match 'TAP|Wintun|Fortinet' } | "
            "Select-Object Name,Status,InterfaceDescription,ifIndex,MacAddress | ConvertTo-Json -Depth 4",
        ),
        powershell_capture(
            "tap-ip",
            f"Get-NetIPAddress -InterfaceAlias '{escaped_alias}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressFamily | ConvertTo-Json -Depth 4",
        ),
        powershell_capture(
            "dns-client",
            "Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.InterfaceAlias -match 'Local Area Connection|VPN|Ethernet|Wi-Fi' } | "
            "Select-Object InterfaceAlias,InterfaceIndex,ServerAddresses | ConvertTo-Json -Depth 5",
        ),
        powershell_capture(
            "route-10",
            "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.DestinationPrefix -like '10.*' -or $_.DestinationPrefix -eq '10.0.0.0/8' } | "
            "Sort-Object DestinationPrefix,RouteMetric,InterfaceMetric | "
            "Select-Object DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric,PolicyStore | ConvertTo-Json -Depth 5",
        ),
    ]
    for host in hosts:
        escaped_host = str(host).replace("'", "''")
        captures.append(powershell_capture(
            f"dns-default:{host}",
            f"Resolve-DnsName '{escaped_host}' -Type A -ErrorAction SilentlyContinue | "
            "Select-Object Name,Type,IPAddress,NameHost | ConvertTo-Json -Depth 4",
            timeout=5,
        ))
        for server in vpn_dns:
            escaped_server = str(server).replace("'", "''")
            captures.append(powershell_capture(
                f"dns-vpn:{host}@{server}",
                f"Resolve-DnsName '{escaped_host}' -Type A -Server '{escaped_server}' -ErrorAction SilentlyContinue | "
                "Select-Object Name,Type,IPAddress,NameHost | ConvertTo-Json -Depth 4",
                timeout=5,
            ))
        captures.append(powershell_capture(
            f"tcp-443:{host}",
            f"Test-NetConnection '{escaped_host}' -Port 443 -InformationLevel Detailed | "
            "Select-Object ComputerName,RemoteAddress,RemotePort,InterfaceAlias,SourceAddress,TcpTestSucceeded | ConvertTo-Json -Depth 4",
            timeout=6,
        ))

    notes = []
    return {
        "tapAlias": alias,
        "hosts": hosts,
        "vpnDnsServers": vpn_dns,
        "trackedRoutes": tracked,
        "captures": captures,
        "notes": notes,
    }


def full_diagnostic(config_path: Path = DEFAULT_CONFIG) -> int:
    STATE_DIR.mkdir(exist_ok=True)
    DIAGNOSTICS_DIR.mkdir(exist_ok=True)
    started = now_text()
    try:
        config = load_config(config_path)
    except SystemExit as exc:
        payload = {"ok": False, "time": started, "error": str(exc)}
        print(json.dumps(payload, indent=2))
        return 2

    append_log(f"\n--- full VPN diagnostic {started} MyVpnClient {MYVPNCLIENT_VERSION} ---")
    diagnostic_config = dict(config)
    diagnostic_config["keepTunnelAliveWhileAppRunning"] = False
    diagnostic_config["diagnosticStopAfterNetworkCheck"] = True
    diagnostic_config["networkCheckFailureTerminates"] = True
    diagnostic_config["connectivityCheckHosts"] = diagnostic_hosts(config)
    diagnostic_config["networkCheckAttempts"] = 1
    diagnostic_config["networkCheckDelaySeconds"] = 1
    diagnostic_config["networkCheckRouteWaitSeconds"] = 5
    diagnostic_config["networkCheckDnsTimeoutSeconds"] = 20
    diagnostic_config["diagnosticFastAfterTunnel"] = True
    error_info = None
    try:
        exit_code = connect_myvpn_once(diagnostic_config)
    except Exception as exc:
        exit_code = 98
        error_info = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
        append_log("MyVpnClient full diagnostic crashed:\n" + error_info["traceback"])
    state = current_myvpn_state_name()
    status_info = status_payload(config_path)
    ok = exit_code == 0 and error_info is None
    health_info = health_payload(config_path)
    network = network_diagnostic_payload(diagnostic_config)
    if ok and isinstance(health_info, dict) and not health_info.get("ok"):
        health_info = {
            **health_info,
            "ok": True,
            "detail": "Diagnostic network check passed before the intentional tunnel cleanup; post-cleanup adapter checks are informational only.",
            "postCleanupDetail": health_info.get("detail"),
        }
    payload = {
        "ok": ok,
        "time": now_text(),
        "started": started,
        "version": MYVPNCLIENT_VERSION,
        "backend": BACKEND_MYVPN,
        "exitCode": exit_code,
        "state": state,
        "summary": "Full VPN diagnostic passed." if ok else "Full VPN diagnostic failed.",
        "status": status_info,
        "health": health_info,
        "network": network,
        "trace": trace_tail(path=RUN_TRACE_FILE),
        "logTail": redact_diagnostic_text(readable_log_file().read_text(encoding="utf-8", errors="replace")[-20000:] if readable_log_file().exists() else ""),
    }
    if error_info:
        payload["error"] = error_info
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_path = DIAGNOSTICS_DIR / f"full-vpn-diagnostic-{timestamp}.json"
    payload["reportPath"] = str(report_path)
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    summary = {
        "ok": ok,
        "time": payload.get("time"),
        "version": MYVPNCLIENT_VERSION,
        "exitCode": exit_code,
        "state": state,
        "reportPath": str(report_path),
    }
    try:
        print(json.dumps(summary, indent=2))
    except OSError as exc:
        append_log(f"Full diagnostic summary print failed: {exc}")
    return 0 if ok else 1


def normalize_route_list(routes) -> list[str]:
    if isinstance(routes, str):
        routes = [item.strip() for item in routes.split(",") if item.strip()]
    if not isinstance(routes, list):
        return []
    result = []
    for route in routes:
        text = route_to_prefix(str(route).strip())
        if text and text not in result and text != "0.0.0.0/0":
            result.append(text)
    return result


def self_test(config_path: Path = DEFAULT_CONFIG) -> int:
    print("== MyVpnClient self-test ==")
    print(f"appDir={APP_DIR}")
    print(f"config={config_path}")
    ok = True
    try:
        config = load_config(config_path)
        print(f"config: ok server={config.get('server')} backend={backend_name(config)}")
    except SystemExit as exc:
        print(f"config: failed {exc}")
        return 2

    print(f"admin: {'yes' if is_admin() else 'no'}")
    if os.name == "nt" and not is_admin():
        ok = False

    for file_name in [
        "myvpnclient_bridge.py",
        "connect-admin.ps1",
        "task-connect.ps1",
        "task-disconnect.ps1",
        "run-helper-task.ps1",
        "myvpn_tunnel",
    ]:
        path = APP_DIR / file_name
        exists = path.exists()
        print(f"file: {file_name} {'ok' if exists else 'missing'}")
        ok = ok and exists

    print(f"myvpn_tunnel adapter kind: {config_value(config, 'adapterKind', 'auto') or 'auto'}")
    print(f"myvpn_tunnel TAP module: {'ok' if packet_adapter_available() else 'unavailable'}")
    ok = ok and packet_adapter_available()

    if os.name == "nt":
        alias = config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
        code, output = run_powershell(
            f"Get-NetAdapter -IncludeHidden -Name '{str(alias).replace("'", "''")}' -ErrorAction SilentlyContinue | "
            "Select-Object Name,Status,InterfaceDescription | Format-List | Out-String",
            timeout=10,
        )
        adapter_ok = code == 0 and bool(output.strip())
        print(f"adapter: {'ok' if adapter_ok else 'missing'} {alias}")
        if output:
            print(output)
        ok = ok and adapter_ok

    return 0 if ok else 1


def health(config_path: Path = DEFAULT_CONFIG) -> int:
    try:
        config = load_config(config_path)
    except SystemExit as exc:
        print(f"health: config failed: {exc}")
        return 2

    print("== MyVpnClient health ==")
    status_code = status(config_path)
    alias = config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
    if os.name != "nt":
        return status_code

    code, tap_ip = run_powershell(
        f"Get-NetIPAddress -InterfaceAlias '{str(alias).replace("'", "''")}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1 -ExpandProperty IPAddress",
        timeout=8,
    )
    tap_ip = tap_ip.strip()
    print(f"tap-ip: {tap_ip or 'none'}")
    ok = status_code == 0 and bool(tap_ip)

    hosts = []
    for host in hosts:
        ps = f"""
$hostName = '{str(host).replace("'", "''")}'
$tapAlias = '{str(alias).replace("'", "''")}'
$addresses = @(Resolve-DnsName $hostName -Type A -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress }} | Select-Object -ExpandProperty IPAddress)
if (-not $addresses -or $addresses.Count -eq 0) {{ Write-Output "unresolved"; exit }}
foreach ($address in $addresses) {{
  $route = Find-NetRoute -RemoteIPAddress $address -ErrorAction SilentlyContinue | Sort-Object {{ $_.RouteMetric + $_.InterfaceMetric }} | Select-Object -First 1
  if ($route) {{
    $iface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    Write-Output "$address|$($iface.InterfaceAlias)"
  }}
}}
"""
        _, output = run_powershell(ps, timeout=ROUTE_CHECK_TIMEOUT_SECONDS)
        routed = any(line.strip().endswith("|" + alias) for line in output.splitlines())
        print(f"route-check: {host} {'ok' if routed else 'pending'} {output.replace(os.linesep, '; ')}")
        ok = ok and routed

    return 0 if ok else 1


def health_payload(config_path: Path = DEFAULT_CONFIG) -> dict:
    try:
        config = load_config(config_path)
    except SystemExit as exc:
        return {"ok": False, "detail": str(exc), "status": status_payload(config_path)}

    status_info = status_payload(config_path)
    alias = config.get("tapInterfaceAlias") or DEFAULT_TAP_ALIAS
    payload = {
        "ok": False,
        "time": now_text(),
        "status": status_info,
        "tapAlias": alias,
        "tapIp": "",
        "routeChecks": [],
        "detail": status_info.get("detail", ""),
    }
    if os.name != "nt":
        payload["ok"] = bool(status_info.get("connected"))
        return payload

    _, tap_ip = run_powershell(
        f"Get-NetIPAddress -InterfaceAlias '{str(alias).replace("'", "''")}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1 -ExpandProperty IPAddress",
        timeout=8,
    )
    payload["tapIp"] = tap_ip.strip()
    hosts = []
    route_ok = True
    for host in hosts:
        ps = f"""
$hostName = '{str(host).replace("'", "''")}'
$tapAlias = '{str(alias).replace("'", "''")}'
$addresses = @(Resolve-DnsName $hostName -Type A -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress }} | Select-Object -ExpandProperty IPAddress)
if (-not $addresses -or $addresses.Count -eq 0) {{ Write-Output "unresolved"; exit }}
foreach ($address in $addresses) {{
  $route = Find-NetRoute -RemoteIPAddress $address -ErrorAction SilentlyContinue | Sort-Object {{ $_.RouteMetric + $_.InterfaceMetric }} | Select-Object -First 1
  if ($route) {{
    $iface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    Write-Output "$address|$($iface.InterfaceAlias)"
  }}
}}
"""
        _, output = run_powershell(ps, timeout=ROUTE_CHECK_TIMEOUT_SECONDS)
        routed = any(line.strip().endswith("|" + alias) for line in output.splitlines())
        route_ok = route_ok and routed
        payload["routeChecks"].append({"host": host, "ok": routed, "detail": output})

    payload["ok"] = bool(status_info.get("connected")) and bool(payload["tapIp"]) and route_ok
    if not payload["ok"] and status_info.get("connected"):
        payload["detail"] = "Network health pending: TAP IP or route check is not ready."
    elif payload["ok"]:
        payload["detail"] = f"Connected: {payload['tapIp']}"
    return payload


def health_json(config_path: Path = DEFAULT_CONFIG) -> int:
    payload = health_payload(config_path)
    health_file = STATE_DIR / "health.json"
    STATE_DIR.mkdir(exist_ok=True)
    health_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if payload.get("ok") else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="MyVpnClient integrated VPN bridge")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Path to config JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("connect")
    sub.add_parser("connect-watch")
    sub.add_parser("connect-interactive")
    sub.add_parser("disconnect")
    sub.add_parser("reset-network")
    sub.add_parser("status")
    sub.add_parser("status-json")
    sub.add_parser("health")
    sub.add_parser("health-json")
    sub.add_parser("preflight-json")
    sub.add_parser("sandbox-check-json")
    sub.add_parser("full-diagnostic")
    sub.add_parser("self-test")
    sub.add_parser("fix-network")
    logs_parser = sub.add_parser("logs")
    logs_parser.add_argument("--lines", type=int, default=80)
    args = parser.parse_args(argv)

    if args.command == "connect":
        return connect(args.config)
    if args.command == "connect-watch":
        return connect(args.config, wait=True)
    if args.command == "connect-interactive":
        return connect_interactive(args.config)
    if args.command == "disconnect":
        return disconnect(args.config)
    if args.command == "reset-network":
        return reset_network(args.config)
    if args.command == "status":
        return status(args.config)
    if args.command == "status-json":
        return status_json(args.config)
    if args.command == "health":
        return health(args.config)
    if args.command == "health-json":
        return health_json(args.config)
    if args.command == "preflight-json":
        return preflight_json(args.config)
    if args.command == "sandbox-check-json":
        return sandbox_check_json(args.config)
    if args.command == "self-test":
        return self_test(args.config)
    if args.command == "fix-network":
        return apply_windows_network_fix(load_config(args.config), wait_for_ip=False)
    if args.command == "logs":
        return logs(args.lines)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        append_log("MyVpnClient bridge crashed:\n" + traceback.format_exc())
        raise
