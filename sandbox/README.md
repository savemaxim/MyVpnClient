# MyVpnClient VPN Lab

This folder is a source-run sandbox for comparing MyVpnClient with the local
OpenConnect checkout without building or installing an MSI.

Default inputs:

- MyVpnClient source: this repository
- OpenConnect source: sibling `openconnect` checkout, or pass `-OpenConnectSource`
- installed/runtime profile config: `C:\ProgramData\MyVpnClient\config.json`
- installed/runtime DPAPI password blob: `C:\ProgramData\MyVpnClient\state\password.dpapi`

Generated output is written under `sandbox\runs\...`.

Secrets are not printed intentionally. Logs are redacted for cookie/password-like
fields, but still treat generated lab logs as local-only.

## Commands

Run from an elevated PowerShell when testing actual tunnel/routes:

```powershell
.\sandbox\run-vpn-lab.ps1 preflight
.\sandbox\run-vpn-lab.ps1 compare-sources
.\sandbox\run-vpn-lab.ps1 collect
.\sandbox\run-vpn-lab.ps1 myvpn-full
.\sandbox\run-vpn-lab.ps1 openconnect-auth
.\sandbox\run-vpn-lab.ps1 openconnect-connect -DurationSeconds 90
```

Suggested learning loop:

1. `preflight` records versions, paths, adapter and route baseline.
2. `openconnect-connect` runs real OpenConnect briefly and records route/DNS state.
3. `myvpn-full` runs the source MyVpn tunnel against the same profile and records trace/report.
4. Compare the newest folders under `sandbox\runs`.

The OpenConnect connect command may require FortiToken/MFA approval.
