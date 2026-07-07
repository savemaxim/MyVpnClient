# MyVpnClient

MyVpnClient is a small VPN client for Fortinet/FortiGate SSL VPN setups where lightweight profiles, logs, diagnostics, and OpenConnect-backed tunnel startup are enough. The primary desktop app is Windows/WinForms; a Linux CLI wrapper is also available for headless hosts.

By default MyVpnClient handles Fortinet login/MFA itself, receives the VPN cookie, and starts OpenConnect for the actual tunnel. The MSI bundles the OpenConnect for Windows runtime under `OpenConnect\`; source runs can use a system OpenConnect install or `openconnect.exe` on `PATH`. The experimental native `myvpn_tunnel` TLS/PPP/TAP engine is still included as a fallback/test path and can be enabled from Settings > Tunnel.

## Features

- WinForms desktop app with tray icon
- Multiple VPN profiles
- Fortinet profile settings
- DPAPI password storage for the current Windows user
- Optional FortiToken push automation
- OpenConnect-backed tunnel transport by default
- Bundled OpenConnect runtime in the MSI
- Experimental native myvpn_tunnel TLS/PPP/TAP transport retained for testing
- Optional post-connect DNS/route repair
- Owner watchdog: if the MyVpnClient process exits or is killed, the helper stops the VPN tunnel process
- Optional persistent tunnel mode that reconnects while MyVpnClient is running, but stops after user disconnect or app exit
- Single-instance app behavior
- Optional localhost-only API
- MSI packaging with Start Menu shortcut and elevated helper tasks

## Technology Stack And Languages

MyVpnClient uses a small mixed Windows stack:

- C# / .NET 8 WinForms for the desktop UI, tray app, profile/settings screens, localhost API, process ownership, and Windows integration.
- Python 3 for the backend bridge, Fortinet authentication flow, diagnostics, route/DNS handling, and the experimental native `myvpn_tunnel` TLS/PPP/TAP backend.
- PowerShell for installer/admin helpers, scheduled task helpers, local build scripts, and connect/disconnect/repair actions that need elevation.
- WiX XML (`.wxs`) for the MSI installer definition.
- YAML for GitHub Actions release automation.
- JavaScript is bundled only as part of the OpenConnect Windows runtime script (`vpnc-script-win.js`); it is not the main application language.

Naming note: `MyVpnTunnel` is a small C# launcher executable under `src/MyVpnTunnel` that starts the Python bridge from the installed app. `backend/myvpn_tunnel` is the Python package that contains the experimental native TLS/PPP/TAP tunnel implementation. They are kept separate because one is a Windows launcher process and the other is importable Python tunnel code. The top-level `tests` and `sandbox` folders are development/validation tooling, not runtime backend code.

## Requirements

For installed MSI users:

- Windows x64
- Python launcher `py` with Python 3.10 or newer available on `PATH`
- No separate OpenConnect install is required; the MSI includes the OpenConnect runtime

For source runs or local MSI builds:

- .NET SDK 8.0 or newer
- Python 3.10 or newer
- OpenConnect for Windows installed, or `openconnect.exe` available on `PATH`
- WiX Toolset 7 CLI and WiX UI/Util extensions when building an MSI locally
- TAP/Wintun adapter support only when testing the native tunnel backend

For Linux CLI use:

- Python 3.10 or newer
- OpenConnect
- vpnc scripts
- root privileges for tunnel creation and route installation

On Debian/Ubuntu:

```bash
sudo apt install python3 openconnect vpnc-scripts
```

## Build From Source

```powershell
dotnet build .\src\MyVpnClient\MyVpnClient.csproj
```

## Run From Source

```powershell
copy .\config.example.json .\config.json
copy .\profiles.example.json .\profiles.json
dotnet run --project .\src\MyVpnClient\MyVpnClient.csproj
```

`profiles.json` is the GUI profile list. `config.json` is the selected/active runtime config still consumed by the backend bridge. Keep both out of git.

Edit profiles from the app settings window before connecting.

## Build Packages Locally

```powershell
.\build-local.ps1 -NoPause
```

The Windows local build publishes a self-contained win-x64 app, stages the MSI payload, copies the OpenConnect runtime from `C:\Program Files\OpenConnect` or an existing `C:\Program Files\MyVpnClient\OpenConnect`, and writes:

```text
artifacts\MyVpnClient-<version>-win-x64.msi
artifacts\MyVpnClient-<version>-win-x64.msi.sha256
```

Build the Linux CLI zip locally:

```powershell
.\build-linux.ps1 -NoPause
```

The Linux build writes:

```text
artifacts\MyVpnClient-<version>-linux-x64.zip
artifacts\MyVpnClient-<version>-linux-x64.zip.sha256
```

If WiX is not already available, install the tool and extensions first:

```powershell
dotnet tool install --global wix --version 7.*
wix eula accept wix7
wix extension add --global WixToolset.UI.wixext/7.0.0
wix extension add --global WixToolset.Util.wixext/7.0.0
```

## GitHub Release Packages

The GitHub workflow `.github/workflows/release-msi.yml` builds release packages on `windows-latest`. It installs OpenConnect with Chocolatey, installs WiX 7, stages the bundled OpenConnect runtime, builds an x64 MSI, packages the Linux CLI zip, uploads checksums, and creates a GitHub Release.

The workflow runs when you push a version tag like:

```powershell
git tag v1.0.106
git push origin v1.0.106
```

It can also be started manually from GitHub Actions with a `1.2.3` version input.

## Install

Install the generated MSI from `artifacts` or from the GitHub Release. The installed `MyVpnClient.exe` requests administrator rights at launch so tunnel startup can avoid a later surprise elevation prompt.

The installer:

- publishes a self-contained `MyVpnClient.exe`
- copies the app to `C:\Program Files\MyVpnClient`
- bundles OpenConnect under `C:\Program Files\MyVpnClient\OpenConnect`
- stores runtime config examples, saved profiles, settings, logs, traces, and diagnostics under `C:\ProgramData\MyVpnClient`
- grants the installing user modify access to the MyVpnClient data folder
- installs elevated helper scheduled tasks
- creates a Start Menu shortcut
- can optionally remove saved configuration and logs during uninstall

Uninstall from Windows Apps & Features.

## Linux CLI

Install the CLI wrapper from a checkout:

```bash
sudo ./install-linux.sh
```

Install or update from the latest GitHub Release on Ubuntu. For a private repository, install and authenticate GitHub CLI first:

```bash
sudo apt-get update
sudo apt-get install -y gh unzip python3 openconnect vpnc-scripts
gh auth login
```

Then fetch and run the installer through `gh`:

```bash
gh api repos/OWNER/REPOSITORY/contents/install-linux.sh --jq .content | base64 -d > /tmp/install-myvpnclient.sh
chmod +x /tmp/install-myvpnclient.sh
/tmp/install-myvpnclient.sh --from-release
```

To install a specific version:

```bash
/tmp/install-myvpnclient.sh --from-release 1.0.145
```

The release installer downloads `MyVpnClient-<version>-linux-x64.zip`, copies it to `/opt/myvpnclient`, and installs `/usr/local/bin/myvpnclient`.

The installer copies runtime files to `/opt/myvpnclient` and creates:

```text
/usr/local/bin/myvpnclient
```

The Linux wrapper stores runtime config and state under:

```text
~/.config/myvpnclient/config.json
~/.config/myvpnclient/state/
```

On first run it creates `config.json` from `config.linux.example.json`. Edit that file before connecting. Do not commit real Linux config, profiles, state, logs, VPN hostnames, usernames, passwords, certificate pins, cookies, assigned VPN IPs, or route dumps.

Start a VPN connection in the background:

```bash
sudo myvpnclient connect
```

Keep the connection in the foreground instead:

```bash
sudo myvpnclient connect-watch
```

Check status:

```bash
myvpnclient status
```

Check the installed version:

```bash
myvpnclient version
```

The text status includes state, uptime, server, and VPN IP when available.

Follow logs:

```bash
myvpnclient logs
```

`myvpnclient logs` prints the last 100 lines and follows new log output until `Ctrl+C`. For one-shot output:

```bash
myvpnclient logs --lines 200 --no-follow
```

Disconnect:

```bash
sudo myvpnclient disconnect
```

The Linux CLI uses OpenConnect by default. `openconnectDpdSeconds` defaults to `300`, which passes `--force-dpd=300` on the next connection. Set it to `0` to omit `--force-dpd`; OpenConnect or the VPN server may still emit PPP DPD echo messages.

For subnet routing through a Linux host, enable IPv4 forwarding and advertise only routes you are allowed to route:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

If another node already advertises the same route, disable the duplicate route or choose which node should be primary in your routing controller.

## Local API

The localhost API is disabled by default. Enable it from Settings.

Default port: `17873`

```powershell
Invoke-RestMethod http://127.0.0.1:17873/status
Invoke-RestMethod http://127.0.0.1:17873/profiles
Invoke-RestMethod http://127.0.0.1:17873/health
Invoke-RestMethod http://127.0.0.1:17873/trace
Invoke-RestMethod -Method Post "http://127.0.0.1:17873/connect?profile=Example%20VPN"
Invoke-RestMethod -Method Post http://127.0.0.1:17873/disconnect
```

On Linux, start the same local API with:

```bash
myvpnclient serve-api
```

or from a checkout:

```bash
./myvpnclient-linux serve-api
```

The API returns profile names/servers/protocols only. It does not return usernames or passwords. `/health` returns structured backend status; `/trace` returns the current trace and route-owner file path.

The API has no authentication. Keep the default localhost bind unless access from trusted machines is required:

```bash
myvpnclient serve-api --bind 0.0.0.0 --port 17873
```

On a trusted private network host, install and run the API as a systemd service bound only to the private interface address:

```bash
sudo ./install-linux.sh --install-api-service --api-bind <private-ip> --api-port 17873
```

The generated service is `myvpnclient-api.service`, sets `HOME=/root` for headless systemd launches, and restarts automatically.


## Notes

MyVpnClient needs elevated rights on Windows to create/open adapters and install routes. The app manifest requests administrator rights at launch, and helper scheduled tasks are still installed for connect/disconnect/repair actions.

The OpenConnect tunnel path is the recommended/default mode. MyVpnClient still owns Fortinet authentication, MFA push, trace logging, and lifecycle cleanup; OpenConnect owns the network tunnel transport. Runtime lookup prefers `OpenConnect\openconnect.exe` beside the installed app, then system OpenConnect locations, then `openconnect` on `PATH`. By default MyVpnClient lets OpenConnect choose or create the Windows Wintun adapter and then tracks the actual adapter name from OpenConnect/Windows. `openconnectInterfaceAlias` remains the preferred logical name (`MyVpnClient` by default); set `openconnectForceInterfaceAlias=true` only when that exact adapter is known to exist. Settings > Tunnel exposes OpenConnect DPD seconds (`--force-dpd`, default 300) and reconnect timeout seconds (`--reconnect-timeout`, default 60). Changing DPD affects the next connection only; 0 omits `--force-dpd`, but OpenConnect/server defaults may still emit PPP DPD echo requests. Longer values such as 600 are allowed but make dead tunnels take longer to be noticed.

The integrated `myvpn_tunnel` backend remains experimental. It can negotiate LCP/IPCP and read/write Wintun or TAP-Windows adapters, but it is slower and less mature than OpenConnect. The MSI no longer packages OpenSSL DLLs for the old native DTLS experiment.

Diagnostics create a redacted ZIP bundle under `C:\ProgramData\MyVpnClient\state\diagnostics` and open that folder when the run completes.

Enable `Keep tunnel alive while MyVpnClient is running` in Settings > Tunnel for FortiClient-like persistence. MyVpnClient will reconnect dropped tunnels while the app owner process is alive. It will not reconnect after a clean disconnect, authentication failure, or when MyVpnClient exits/is killed.

## License

MyVpnClient source code is licensed under the MIT License. See `LICENSE`.

Third-party projects and trademark notes are listed in `THIRD_PARTY_NOTICES.md`.

Before publishing to GitHub, review `GITHUB_PUBLISH_CHECKLIST.md`.

Do not commit `config.json`, `profiles.json`, logs, DPAPI password files, or anything under `state/`.
