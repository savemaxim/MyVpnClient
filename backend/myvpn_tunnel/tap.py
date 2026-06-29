from __future__ import annotations

import ctypes
from ctypes import wintypes
import ipaddress
import os
import queue
import subprocess
import threading
import tempfile
import time
import winreg


GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_IO_PENDING = 997
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

NETDEV_GUID = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
TAP_COMPONENT_IDS = {"tap0901", "tap_ovpnconnect"}
WINTUN_RING_CAPACITY = 0x400000
ERROR_NO_MORE_ITEMS = 259
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


def new_event():
    event = ctypes.windll.kernel32.CreateEventW(None, True, False, None)
    if not event:
        raise ctypes.WinError()
    return wintypes.HANDLE(event)


def reset_event(event) -> None:
    if not ctypes.windll.kernel32.ResetEvent(event):
        raise ctypes.WinError()


def ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    return (device_type << 16) | (access << 14) | (function << 2) | method


TAP_IOCTL_GET_VERSION = ctl_code(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
TAP_IOCTL_SET_MEDIA_STATUS = ctl_code(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
TAP_IOCTL_CONFIG_TUN = ctl_code(FILE_DEVICE_UNKNOWN, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)


class TapDevice:
    def __init__(self, alias: str, *, log=print) -> None:
        if os.name != "nt":
            raise OSError("TAP device support is Windows-only")
        self.alias = alias
        self.log = log
        self.guid = find_tap_guid(alias)
        if not self.guid:
            raise OSError(f"No TAP-Windows adapter found with alias '{alias}'")
        self.handle = None
        self.read_event = None
        self.write_event = None
        self.reader_thread = None
        self.reader_stop = threading.Event()

    def open(self) -> None:
        path = rf"\\.\Global\{self.guid}.tap"
        handle = ctypes.windll.kernel32.CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            raise ctypes.WinError()
        self.handle = wintypes.HANDLE(handle)
        if self.read_event is None:
            self.read_event = new_event()
        if self.write_event is None:
            self.write_event = new_event()
        major, minor, build = self.get_version()
        self.log(f"myvpn_tunnel opened TAP '{self.alias}' ({self.guid}), driver {major}.{minor}.{build}.")
        self.set_media_status(True)

    def configure(
        self,
        ipv4: str,
        *,
        routes: list[str] | None = None,
        dns: list[str] | None = None,
        metric: int = 1,
        mtu: int = 1351,
    ) -> None:
        if self.handle is None:
            self.open()
        address = int.from_bytes(ipaddress.IPv4Address(ipv4).packed, "little")
        data = (wintypes.ULONG * 3)(address, 0, 0)
        self.ioctl(TAP_IOCTL_CONFIG_TUN, data)
        self.set_media_status(True)
        configure_windows_interface(self.alias, ipv4, routes or [], dns or [], metric, self.log, mtu=mtu)
        self.log(f"myvpn_tunnel configured TAP point-to-point address {ipv4}; mtu={mtu}.")

    def start_reader(self, target: queue.Queue[bytes], notify=None) -> None:
        if self.handle is None:
            self.open()
        if self.read_event is None:
            self.read_event = new_event()

        def worker() -> None:
            buffer = ctypes.create_string_buffer(65536)
            event = self.read_event
            while not self.reader_stop.is_set():
                read = wintypes.DWORD()
                overlapped = OVERLAPPED()
                overlapped.hEvent = event
                try:
                    reset_event(event)
                    ok = ctypes.windll.kernel32.ReadFile(
                        self.handle,
                        buffer,
                        len(buffer),
                        ctypes.byref(read),
                        ctypes.byref(overlapped),
                    )
                    if not ok:
                        err = ctypes.windll.kernel32.GetLastError()
                        if err != ERROR_IO_PENDING:
                            self.log(f"myvpn_tunnel TAP read failed: {ctypes.WinError(err)}")
                            return
                        ok = ctypes.windll.kernel32.GetOverlappedResult(
                            self.handle,
                            ctypes.byref(overlapped),
                            ctypes.byref(read),
                            True,
                        )
                        if not ok:
                            err = ctypes.windll.kernel32.GetLastError()
                            self.log(f"myvpn_tunnel TAP overlapped read failed: {ctypes.WinError(err)}")
                            return
                    if read.value:
                        target.put(buffer.raw[: read.value])
                        if notify:
                            notify()
                except OSError as exc:
                    if not self.reader_stop.is_set():
                        self.log(f"myvpn_tunnel TAP read failed: {exc}")
                    return

        self.reader_thread = threading.Thread(target=worker, name="myvpn_tunnel-tap-reader", daemon=True)
        self.reader_thread.start()

    def write(self, packet: bytes) -> int:
        if self.handle is None:
            return 0
        if self.write_event is None:
            self.write_event = new_event()
        written = wintypes.DWORD()
        data = ctypes.create_string_buffer(packet)
        event = self.write_event
        overlapped = OVERLAPPED()
        overlapped.hEvent = event
        try:
            reset_event(event)
            ok = ctypes.windll.kernel32.WriteFile(
                self.handle,
                data,
                len(packet),
                ctypes.byref(written),
                ctypes.byref(overlapped),
            )
            if not ok:
                err = ctypes.windll.kernel32.GetLastError()
                if err != ERROR_IO_PENDING:
                    self.log(f"myvpn_tunnel TAP write failed: {ctypes.WinError(err)}")
                    return -1
                ok = ctypes.windll.kernel32.GetOverlappedResult(
                    self.handle,
                    ctypes.byref(overlapped),
                    ctypes.byref(written),
                    True,
                )
                if not ok:
                    err = ctypes.windll.kernel32.GetLastError()
                    self.log(f"myvpn_tunnel TAP overlapped write failed: {ctypes.WinError(err)}")
                    return -1
            return int(written.value)
        except OSError as exc:
            self.log(f"myvpn_tunnel TAP write failed: {exc}")
            return -1

    def close(self) -> None:
        self.reader_stop.set()
        if self.handle is not None:
            try:
                ctypes.windll.kernel32.CancelIoEx(self.handle, None)
            except Exception:
                pass
            self.set_media_status(False)
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=1.0)
        self.reader_thread = None
        for attr in ("read_event", "write_event"):
            event = getattr(self, attr, None)
            if event is not None:
                ctypes.windll.kernel32.CloseHandle(event)
                setattr(self, attr, None)

    def get_version(self) -> tuple[int, int, int]:
        data = (wintypes.ULONG * 3)()
        self.ioctl(TAP_IOCTL_GET_VERSION, data)
        return int(data[0]), int(data[1]), int(data[2])

    def set_media_status(self, connected: bool) -> None:
        data = wintypes.ULONG(1 if connected else 0)
        self.ioctl(TAP_IOCTL_SET_MEDIA_STATUS, data)

    def ioctl(self, code: int, data) -> None:
        returned = wintypes.DWORD()
        ok = ctypes.windll.kernel32.DeviceIoControl(
            self.handle,
            code,
            ctypes.byref(data),
            ctypes.sizeof(data),
            ctypes.byref(data),
            ctypes.sizeof(data),
            ctypes.byref(returned),
            None,
        )
        if not ok:
            raise ctypes.WinError()


def find_tap_guid(alias: str) -> str | None:
    connections = rf"SYSTEM\CurrentControlSet\Control\Network\{NETDEV_GUID}"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, connections) as root:
        index = 0
        while True:
            try:
                guid = winreg.EnumKey(root, index)
                index += 1
            except OSError:
                break
            try:
                with winreg.OpenKey(root, rf"{guid}\Connection") as conn:
                    name, _ = winreg.QueryValueEx(conn, "Name")
                if name.lower() == alias.lower() and is_tap_component(guid):
                    return guid
            except OSError:
                continue
    return None


def is_tap_component(guid: str) -> bool:
    adapter_root = rf"SYSTEM\CurrentControlSet\Control\Class\{NETDEV_GUID}"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, adapter_root) as root:
        index = 0
        while True:
            try:
                subkey = winreg.EnumKey(root, index)
                index += 1
            except OSError:
                return False
            try:
                with winreg.OpenKey(root, subkey) as adapter:
                    net_guid, _ = winreg.QueryValueEx(adapter, "NetCfgInstanceId")
                    component, _ = winreg.QueryValueEx(adapter, "ComponentId")
                if net_guid.lower() == guid.lower():
                    return str(component).lower() in TAP_COMPONENT_IDS
            except OSError:
                continue


def _netsh_quote(value: str) -> str:
    return '"' + str(value).replace('"', r'\"') + '"'


def _run_netsh_batch(lines: list[str]) -> tuple[int, str, int]:
    started = time.monotonic()
    path = None
    try:
        fd, path = tempfile.mkstemp(prefix="myvpn-netsh-", suffix=".txt")
        with os.fdopen(fd, "w", encoding="ascii", newline="\r\n") as handle:
            handle.write("\n".join(lines))
            handle.write("\n")
        result = subprocess.run(
            ["netsh.exe", "-f", path],
            capture_output=True,
            text=True,
            check=False,
            creationflags=CREATE_NO_WINDOW,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return int(result.returncode), (result.stdout + result.stderr).strip(), elapsed_ms
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _flush_dns() -> int:
    started = time.monotonic()
    subprocess.run(
        ["ipconfig", "/flushdns"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )
    return int((time.monotonic() - started) * 1000)


def configure_windows_interface(alias: str, ipv4: str, routes: list[str], dns: list[str], metric: int, log, *, mtu: int = 1351) -> None:
    configure_started = time.monotonic()
    route_prefixes = [route_to_prefix(route) for route in routes]
    route_prefixes.extend(f"{server}/32" for server in dns if server and ":" not in server)
    route_prefixes = list(dict.fromkeys(route for route in route_prefixes if route))
    dns_servers = [server for server in dns if server]
    iface = _netsh_quote(alias)
    gateway = "0.0.0.0"

    lines: list[str] = [
        f"interface ipv4 set interface {iface} metric={int(metric)} store=active",
        f"interface ipv4 set subinterface {iface} mtu={int(mtu)} store=active",
        f"interface ipv4 set address name={iface} source=static address={ipv4} mask=255.255.255.255 gateway=none store=active",
    ]
    if dns_servers:
        lines.append(f"interface ipv4 set dnsservers name={iface} source=static address={dns_servers[0]} register=none validate=no")
        for server in dns_servers[1:]:
            lines.append(f"interface ipv4 add dnsservers name={iface} address={server} validate=no")

    # OpenConnect's Windows script adds the routes it needs without first
    # deleting the whole split table. Doing the same keeps repeat connects fast;
    # "object already exists" is treated as a non-fatal netsh result below.
    for route in route_prefixes:
        lines.append(f"interface ipv4 add route prefix={route} interface={iface} nexthop={gateway} metric=1 store=active")

    code, output, netsh_ms = _run_netsh_batch(lines)
    lower_output = output.lower()
    hard_failure = (
        code != 0
        and not any(text in lower_output for text in ("element not found", "object already exists", "the object already exists", "cannot find"))
    )
    if hard_failure:
        log(f"Fast netsh TAP configuration failed with exit={code}; falling back to PowerShell configurator. Output: {output[:1200]}")
        return _configure_windows_interface_powershell(alias, ipv4, routes, dns, metric, log, mtu=mtu)

    ready_started = time.monotonic()
    # Route installation is synchronous enough for immediate probes; keep only
    # a tiny grace period for Windows to publish address/DNS state to clients.
    time.sleep(0.1)
    ready_wait_ms = int((time.monotonic() - ready_started) * 1000)
    flush_ms = _flush_dns()
    elapsed_ms = int((time.monotonic() - configure_started) * 1000)
    non_fatal_netsh = code != 0 and not hard_failure
    if output and code != 0 and not non_fatal_netsh:
        log(f"Fast netsh TAP configuration completed with non-fatal netsh exit={code}; output: {output[:1200]}")
    log(
        f"Configured Windows TAP interface {alias}: method=netsh-fast routeMode=add-only ip={ipv4} gateway={gateway} mtu={mtu} "
        f"routes={len(route_prefixes)} dns={','.join(dns_servers)} metric={metric} netshExit={code} "
        f"nonFatalNetsh={str(non_fatal_netsh).lower()} netshMs={netsh_ms} readyWaitMs={ready_wait_ms} "
        f"flushDnsMs={flush_ms} elapsedMs={elapsed_ms}"
    )


def _configure_windows_interface_powershell(alias: str, ipv4: str, routes: list[str], dns: list[str], metric: int, log, *, mtu: int = 1351) -> None:
    route_prefixes = [route_to_prefix(route) for route in routes]
    route_prefixes.extend(f"{server}/32" for server in dns if server and ":" not in server)
    route_prefixes = list(dict.fromkeys(route for route in route_prefixes if route))
    route_literal = "@(" + ",".join("'" + route.replace("'", "''") + "'" for route in route_prefixes if route) + ")"
    dns_literal = "@(" + ",".join("'" + server.replace("'", "''") + "'" for server in dns if server) + ")"
    alias_literal = alias.replace("'", "''")
    # TAP split routes are on-link. Using the assigned 10.0.125.x address as
    # NextHop can make Windows accept the route but blackhole DNS/Jira traffic.
    gateway = "0.0.0.0"
    script = f"""
$ErrorActionPreference = 'Continue'
$configureStarted = Get-Date
$ifAlias = '{alias_literal}'
$ip = '{ipv4}'
$gateway = '{gateway}'
$routes = {route_literal}
$dns = {dns_literal}
$metric = {int(metric)}
$mtu = {int(mtu)}
Get-NetIPAddress -InterfaceAlias $ifAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object {{ $_.IPAddress -ne $ip }} |
  Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
$ifInfo = Get-NetIPInterface -InterfaceAlias $ifAlias -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
$ifIndex = [int]$ifInfo.InterfaceIndex
$existingRoutes = @{{}}
@(Get-NetRoute -InterfaceIndex $ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue).ForEach({{ $existingRoutes[$_.DestinationPrefix] = $true }})

$netshFile = Join-Path $env:TEMP ("myvpn-netsh-" + [guid]::NewGuid().ToString("N") + ".txt")
$lines = New-Object 'System.Collections.Generic.List[string]'
[void]$lines.Add("interface ipv4 set interface $ifIndex metric=$metric store=active")
[void]$lines.Add("interface ipv4 set subinterface $ifIndex mtu=$mtu store=active")
[void]$lines.Add("interface ipv4 set address name=$ifIndex source=static address=$ip mask=255.255.255.255 gateway=none store=active")
if ($dns.Count -gt 0) {{
  [void]$lines.Add("interface ipv4 delete dnsservers $ifIndex all")
  foreach ($server in $dns) {{
    if (-not $server) {{ continue }}
    [void]$lines.Add("interface ipv4 add dnsservers $ifIndex $server validate=no")
  }}
}}
$routeAddCount = 0
$routeSkipCount = 0
foreach ($route in $routes) {{
  if (-not $route) {{ continue }}
  if ($existingRoutes.ContainsKey($route)) {{
    $routeSkipCount += 1
    continue
  }}
  [void]$lines.Add("interface ipv4 add route prefix=$route interface=$ifIndex nexthop=$gateway metric=1 store=active")
  $routeAddCount += 1
}}
Set-Content -LiteralPath $netshFile -Value $lines -Encoding ASCII
$netshOutput = & netsh.exe -f $netshFile 2>&1
$netshExit = $LASTEXITCODE
Remove-Item -LiteralPath $netshFile -Force -ErrorAction SilentlyContinue

$installedRoutes = @{{}}
@(Get-NetRoute -InterfaceIndex $ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue).ForEach({{ $installedRoutes[$_.DestinationPrefix] = $true }})
$missingRoutes = @()
foreach ($route in $routes) {{
  if (-not $route) {{ continue }}
  if (-not $installedRoutes.ContainsKey($route)) {{
    $missingRoutes += $route
  }}
}}
$fallbackCount = 0
foreach ($route in $missingRoutes) {{
  New-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $route -NextHop $gateway -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
  $fallbackCount += 1
}}
if ($fallbackCount -gt 0) {{
  $installedRoutes = @{{}}
  @(Get-NetRoute -InterfaceIndex $ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue).ForEach({{ $installedRoutes[$_.DestinationPrefix] = $true }})
}}

$routeVerified = 0
$routeFailures = @()
foreach ($route in $routes) {{
  if (-not $route) {{ continue }}
  if ($installedRoutes.ContainsKey($route)) {{
    $routeVerified += 1
  }} else {{
    $routeFailures += "$route via $gateway if $ifIndex failed"
  }}
}}
if ($routeFailures.Count -gt 0) {{
  Write-Output "Route install failures: $($routeFailures -join '; ')"
  if ($netshOutput) {{
    Write-Output "netsh output: $($netshOutput -join ' ')"
  }}
}}
$readyStarted = Get-Date
# Give Windows a short moment to publish address/DNS state to clients.
Start-Sleep -Milliseconds 100
$readyAttempts = 1
$readyWaitMs = [int]((Get-Date) - $readyStarted).TotalMilliseconds
ipconfig /flushdns | Out-Null
$elapsedMs = [int]((Get-Date) - $configureStarted).TotalMilliseconds
Write-Output "Configured Windows TAP interface ${{ifAlias}}: ip=$ip gateway=$gateway ifIndex=$ifIndex mtu=$mtu routes=$($routes.Count) addedRoutes=$routeAddCount skippedRoutes=$routeSkipCount fallbackRoutes=$fallbackCount verifiedRoutes=$routeVerified dns=$($dns -join ',') metric=$metric netshExit=$netshExit readyWaitMs=$readyWaitMs readyAttempts=$readyAttempts elapsedMs=$elapsedMs"
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )
    output = (result.stdout + result.stderr).strip()
    if output:
        log(output)

def vpn_peer_gateway(ipv4: str) -> str:
    try:
        address = ipaddress.IPv4Address(ipv4)
    except ValueError:
        return "0.0.0.0"
    # Match OpenConnect's Windows TAP script: for a tunnel, the gateway is a
    # routing placeholder, so use the assigned tunnel IP instead of inventing a
    return str(address)


def route_to_prefix(route: str) -> str:
    if "/" not in route:
        return route
    address, mask = route.split("/", 1)
    try:
        if "." in mask:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            return f"{address}/{prefix}"
        return route
    except ValueError:
        return route


class WintunDevice:
    def __init__(self, alias: str, *, log=print) -> None:
        if os.name != "nt":
            raise OSError("Wintun support is Windows-only")
        self.alias = alias
        self.log = log
        self.dll = None
        self.adapter = None
        self.session = None
        self.reader_stop = threading.Event()

    def open(self) -> None:
        self.dll = load_wintun()
        self.adapter = self.dll.WintunOpenAdapter(self.alias)
        if not self.adapter:
            self.adapter = self.dll.WintunCreateAdapter(self.alias, "MyVpnClient", None)
        if not self.adapter:
            raise ctypes.WinError(ctypes.get_last_error())
        version = self.dll.WintunGetRunningDriverVersion()
        self.session = self.dll.WintunStartSession(self.adapter, WINTUN_RING_CAPACITY)
        if not self.session:
            raise ctypes.WinError(ctypes.get_last_error())
        self.log(f"myvpn_tunnel opened Wintun '{self.alias}', driver {(version >> 16) & 0xff}.{version & 0xff}.")

    def configure(
        self,
        ipv4: str,
        *,
        routes: list[str] | None = None,
        dns: list[str] | None = None,
        metric: int = 1,
        mtu: int = 1351,
    ) -> None:
        if self.session is None:
            self.open()
        configure_windows_interface(self.alias, ipv4, routes or [], dns or [], metric, self.log, mtu=mtu)
        self.log(f"myvpn_tunnel configured Wintun address {ipv4}; mtu={mtu}.")

    def start_reader(self, target: queue.Queue[bytes], notify=None) -> None:
        if self.session is None:
            self.open()

        def worker() -> None:
            while not self.reader_stop.is_set():
                size = wintypes.DWORD()
                packet_ptr = self.dll.WintunReceivePacket(self.session, ctypes.byref(size))
                if not packet_ptr:
                    err = ctypes.get_last_error()
                    if err == ERROR_NO_MORE_ITEMS:
                        time.sleep(0.001)
                        continue
                    self.log(f"myvpn_tunnel Wintun read failed: {ctypes.WinError(err)}")
                    return
                try:
                    target.put(ctypes.string_at(packet_ptr, size.value))
                    if notify:
                        notify()
                finally:
                    self.dll.WintunReleaseReceivePacket(self.session, packet_ptr)

        threading.Thread(target=worker, name="myvpn_tunnel-wintun-reader", daemon=True).start()

    def write(self, packet: bytes) -> int:
        if self.session is None:
            return 0
        packet_ptr = self.dll.WintunAllocateSendPacket(self.session, len(packet))
        if not packet_ptr:
            self.log(f"myvpn_tunnel Wintun allocate-send failed: {ctypes.WinError(ctypes.get_last_error())}")
            return -1
        ctypes.memmove(packet_ptr, packet, len(packet))
        self.dll.WintunSendPacket(self.session, packet_ptr)
        return len(packet)

    def close(self) -> None:
        self.reader_stop.set()
        if self.dll and self.session:
            self.dll.WintunEndSession(self.session)
            self.session = None
        if self.dll and self.adapter:
            self.dll.WintunCloseAdapter(self.adapter)
            self.adapter = None


def load_wintun():
    dll = ctypes.WinDLL("wintun.dll", use_last_error=True)
    dll.WintunCreateAdapter.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
    dll.WintunCreateAdapter.restype = ctypes.c_void_p
    dll.WintunOpenAdapter.argtypes = [wintypes.LPCWSTR]
    dll.WintunOpenAdapter.restype = ctypes.c_void_p
    dll.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
    dll.WintunCloseAdapter.restype = None
    dll.WintunGetRunningDriverVersion.argtypes = []
    dll.WintunGetRunningDriverVersion.restype = wintypes.DWORD
    dll.WintunStartSession.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    dll.WintunStartSession.restype = ctypes.c_void_p
    dll.WintunEndSession.argtypes = [ctypes.c_void_p]
    dll.WintunEndSession.restype = None
    dll.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    dll.WintunReceivePacket.restype = ctypes.c_void_p
    dll.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    dll.WintunReleaseReceivePacket.restype = None
    dll.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    dll.WintunAllocateSendPacket.restype = ctypes.c_void_p
    dll.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    dll.WintunSendPacket.restype = None
    return dll


def open_packet_device(kind: str, alias: str, *, log=print):
    normalized = (kind or "auto").strip().lower()
    errors: list[str] = []
    if normalized == "auto":
        try:
            device = TapDevice(alias, log=log)
            device.open()
            return device
        except Exception as exc:
            errors.append(f"TAP: {exc}")
    if normalized in {"auto", "wintun"}:
        try:
            device = WintunDevice(alias, log=log)
            device.open()
            return device
        except Exception as exc:
            errors.append(f"Wintun: {exc}")
            if normalized == "wintun":
                raise
    if normalized in {"tap", "tap-windows"}:
        try:
            device = TapDevice(alias, log=log)
            device.open()
            return device
        except Exception as exc:
            errors.append(f"TAP: {exc}")
            if normalized != "auto":
                raise
    raise OSError("No packet adapter opened; " + "; ".join(errors))
