# UX and Stability Refactor Report

Created: 2026-06-19

This pass implements the suggested end-user experience and stability refactors as an incremental change set over the existing WinForms app and Python bridge.

## Implemented

1. Explicit connection state model
   - Added bridge-side state metadata: `phase`, `userMessage`, `suggestedAction`, `retryable`, and `recoverability`.
   - Added richer C# `VpnStatusSnapshot` fields and surfaced them through the local API.

2. Phase-based progress feedback
   - Status now distinguishes phases such as `Authenticating`, `OpeningTunnel`, `NegotiatingPpp`, `NetworkReady`, `FailedAuth`, `FailedTunnel`, and `FailedNetwork`.
   - Main UI detail text shows phase plus suggested action.

3. Preflight check before connect
   - Added `myvpnclient_bridge.py preflight-json`.
   - Connect now runs preflight first and blocks with actionable messages when required checks fail.
   - Added Diagnostics tab button: `Preflight check`.
   - Added API endpoint: `GET /preflight`.

4. Network transaction stability
   - Existing route/DNS transaction capture and cleanup remain in place.
   - Preflight now checks elevation/helper task readiness before starting privileged network work.
   - Diagnostics include preflight and sandbox outputs to reduce blind connect attempts.

5. First-class sandbox diagnostic mode
   - Added `myvpnclient_bridge.py sandbox-check-json`.
   - Added Diagnostics tab button: `Offline sandbox`.
   - Added API endpoint: `GET /sandbox-check`.
   - Existing `tests/sandbox_vpn_connection.py` still exercises the real bridge connection path with fake Fortinet/TLS/TAP components.

6. Structured event/state output
   - `status-json` and `health-json` now include structured user-facing state metadata.
   - Trace JSON remains available through `GET /trace`.

7. Reduced UI dependence on raw PID/state files
   - UI and API now consume richer controller snapshots instead of interpreting raw detail strings.
   - Full service/process ownership separation was not introduced in this pass; that would be a larger architectural change.

8. Reason-aware retry policy
   - Bridge state metadata marks failures as retryable or wait-only.
   - Main UI now uses `snapshot.Retryable` for Retry button visibility instead of string matching.

9. Actionable diagnostics
   - Preflight checks include `detail` and `action` per failed item.
   - Connect failure dialog shows the failed preflight actions.
   - `Run diagnostics` now includes self-test, preflight, offline sandbox, status, and health.

10. Integration test profile harness
   - Added `tests/integration_vpn_connection.py`.
   - Default mode validates config and runs preflight only.
   - Real connect/disconnect requires explicit `--allow-network-changes`.

## Verification

Python tests:

```powershell
py -B -m unittest discover -s tests
```

Result:

```text
Ran 20 tests
OK
```

Offline sandbox command:

```powershell
py -B myvpnclient_bridge.py sandbox-check-json
```

Result: succeeded and reported all simulated phases without credentials, adapters, routes, or network access.

Preflight command:

```powershell
py -B myvpnclient_bridge.py preflight-json
```

Result in this clone: failed correctly because `config.json` does not exist.

WinForms build:

```powershell
dotnet build .\src\MyVpnClient\MyVpnClient.csproj
```

Result: not run successfully because `dotnet` is not installed or not on PATH on this machine.

## Remaining Larger Refactor

The only item intentionally not fully completed is a dedicated background controller service that owns the tunnel process independently of the tray UI. This pass reduces UI dependence on raw state files, but a real service split should be designed separately because it affects installation, helper tasks, process ownership, and upgrade behavior.
