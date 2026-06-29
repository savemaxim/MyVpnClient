# MyVpn Tunnel Analysis Report

Created: 2026-06-19

Scope: `myvpn_tunnel` Python engine, `myvpnclient_bridge.py` connection orchestration, and offline tunnel testability.

## Summary

The tunnel code has a useful separation between Fortinet authentication, TLS/DTLS transport, PPP negotiation, and packet adapter handling. Existing unit coverage was mostly parser/PPP fixture coverage. I added offline logical and performance checks so the tunnel path can be tested without Administrator rights, real VPN credentials, TAP/Wintun, route changes, or network access.

Main result: the logical suite passes, but review found two real correctness risks in DTLS/no-TAP behavior and one protocol-diagnostics weakness in TLS tunnel open handling.

## Added Test Assets

- `tests/sandbox_vpn_connection.py`
  - Exercises `connect_myvpn_once` with fake Fortinet auth, fake TLS tunnel, fake TAP, temp state files, and no admin/network access.
- `tests/test_tunnel_logical_edges.py`
  - Adds edge tests for PPP HTTP rejection, malformed PPP options, no-TAP readiness behavior, route mask fallback, IPv4-before-TAP behavior, and socket send contract.
- `tests/benchmark_tunnel_performance.py`
  - Benchmarks PPP frame parsing and outgoing frame wrapping/sending with fake sockets.

## Commands Run

```powershell
py -B -m unittest discover -s tests
py -B tests\sandbox_vpn_connection.py
py -B tests\benchmark_tunnel_performance.py
```

## Logical Test Results

`py -B -m unittest discover -s tests`

Result:

```text
Ran 18 tests in 0.013s
OK
```

Sandbox result:

```text
sandbox result: PASS
```

The sandbox reached these states:

```text
authenticating -> authenticated -> tls-tunnel-running -> ppp-lcp-start -> ppp-lcp-opened -> ppp-ipcp-start -> network-ready
```

It also verified route normalization from `10.44.0.0/255.255.0.0` to `10.44.0.0/16`, DNS tracking, trace output, and clean removal of the transient state file after a clean tunnel exit.

## Performance Results

`py -B tests\benchmark_tunnel_performance.py`

Environment: local Windows Python, fake socket, 50,000 frames, 128-byte IPv4 payload.

| Benchmark | Frames | Elapsed | Throughput |
| --- | ---: | ---: | ---: |
| streaming_parse | 50,000 | 0.0520s | 961k frames/s |
| batch_parse | 50,000 | 0.0491s | 1.02M frames/s |
| flush_outgoing | 50,000 | 0.2851s | 175k frames/s |

Interpretation:

- PPP frame parsing is not the current bottleneck in offline CPU-only conditions.
- Outgoing wrapping/sending is materially slower than parsing, mostly due one send call per PPP frame and per-frame object construction. Real VPN throughput will likely be dominated by TLS/DTLS/socket/TAP overhead before this parser becomes the first bottleneck.
- The current benchmark does not model real packet adapter latency, kernel copy costs, TLS encryption, MTU effects, or network RTT.

## Findings

### High: DTLS Mode Cannot Send PPP Frames With Current Socket Contract

Evidence:

- `backend/myvpn_tunnel/dtls.py:102` defines `OpenSslDtlsSocket`.
- `backend/myvpn_tunnel/dtls.py:125` exposes `OpenSslDtlsSocket.sendall(...)`.
- `backend/myvpn_tunnel/ppp.py:419` defines `FortinetPppEngine.sendall(...)`.
- `backend/myvpn_tunnel/ppp.py:424` calls `self.sock.send(...)`.

Impact:

When `preferDtls=true`, the DTLS path passes `OpenSslDtlsSocket` into `FortinetPppEngine`. The first outgoing PPP frame uses `.send(...)`, but the DTLS wrapper only implements `.sendall(...)`. That should fail with `AttributeError`, caught by `run()` as a PPP send failure, so DTLS mode is effectively broken on first transmit.

Recommendation:

Add a `send(self, data) -> int` method to `OpenSslDtlsSocket`, or change `FortinetPppEngine.sendall` to prefer socket `.sendall(...)` when `.send(...)` is unavailable. A `send` method is probably cleaner because it preserves the engine's partial-write loop semantics.

### Medium: No-TAP Mode Reaches PPP Ready Internally But Never Reports Connected

Evidence:

- `myvpnclient_bridge.py:788` returns no adapter when `enableTap=false`.
- `backend/myvpn_tunnel/ppp.py:200` enters TAP setup only when `self.tap` exists.
- `backend/myvpn_tunnel/ppp.py:210` calls `on_ready` only inside the TAP block.
- `myvpnclient_bridge.py:928` treats only state `network-ready` as connected.

Impact:

When PPP negotiation succeeds but no TAP adapter is used, `FortinetPppEngine` can set its internal phase to `network-ready`, but it does not call the bridge `on_ready` callback. The bridge therefore records `ppp-network-ready` via `on_phase`, not `network-ready`, and health/status never become connected.

This matters for:

- quick no-adapter testing,
- diagnostic/dry-run connection checks,
- any future packetless tunnel mode.

Recommendation:

Separate "ready notification" from TAP startup. For example, track a `ready_notified` boolean and call `on_ready(self.state.ipv4)` once whenever `state.network_ready` becomes true. Keep TAP `configure/start_reader` guarded by `self.tap`.

### Medium: TLS Tunnel Open Does Not Validate HTTP Response Headers

Evidence:

- `backend/myvpn_tunnel/tunnel.py:42` opens the TLS socket and sends `GET /remote/sslvpn-tunnel`.
- `backend/myvpn_tunnel/tunnel.py:60` always returns `TunnelOpenResult(0, "PPP stream pending", {})`.
- `backend/myvpn_tunnel/tunnel.py:105` contains `_read_response_headers`, but it is not used.
- `backend/myvpn_tunnel/ppp.py:220` treats any `HTTP/` data in the PPP stream as a rejected tunnel request.

Impact:

The open call cannot distinguish a successful tunnel stream from an HTTP rejection at the open boundary. Rejections are reported later by the PPP parser. If a Fortinet endpoint sends HTTP status headers before stream data in some mode, this implementation may also classify even a valid HTTP response prefix as a PPP tunnel failure.

Recommendation:

Decide the expected Fortinet wire behavior explicitly:

- If the server always switches directly to PPP bytes, remove or comment `_read_response_headers` and improve the `open()` result text.
- If headers are expected, call `_read_response_headers()` in `open()` and only enter PPP mode after a validated 2xx response.

### Low: PPP Parser Drops IPv4 Packets Received Before TAP Startup

Evidence:

- `backend/myvpn_tunnel/ppp.py` logs and drops IPv4 packets when `tap_started` is false.

Impact:

This is probably acceptable during negotiation, but early data from the peer can be lost. If Fortinet sends data immediately after IPCP ACK and before TAP configuration completes, the first packets may be dropped.

Recommendation:

If this appears in real traces, buffer a small number of IP packets until TAP is configured, then flush them.

## Performance Notes

The offline benchmark suggests that pure Python frame parsing is adequate for control-plane and moderate data-plane work. The outgoing path is lower throughput because each packet becomes one Fortinet frame and one socket send call. Before optimizing parser internals, measure a real run with:

- packet sizes and MTU distribution,
- TLS versus DTLS mode,
- TAP/Wintun read/write latency,
- `rxPackets` and `txPackets` over time from `state.myvpn_tunnel.json`,
- CPU usage during sustained transfer.

Likely future optimizations, only after real profiling:

- batch outgoing frames where protocol allows it,
- avoid repeated small sends in `flush_outgoing`,
- reduce per-packet logging in hot paths,
- use Wintun path preferentially if TAP read/write overhead dominates.

## Recommended Next Steps

1. Fix the DTLS socket contract first; it is a direct functional blocker for `preferDtls`.
2. Fix no-TAP readiness reporting so sandbox/dry-run checks can report a successful PPP negotiation without requiring an adapter.
3. Clarify and test TLS tunnel HTTP header behavior against a known Fortinet endpoint or captured trace.
4. Add a real integration test mode that uses a redacted config file and requires explicit opt-in before touching adapters/routes.
5. Run the benchmark before and after any PPP hot-path optimization to avoid making readability worse without measurable gain.

## Fix Pass Results

Updated: 2026-06-19

Implemented fixes:

- Added `OpenSslDtlsSocket.send(...)` and made `sendall(...)` reuse it, so DTLS sockets now satisfy the PPP engine send contract.
- Added one-shot PPP ready notification independent of TAP startup, so no-TAP/dry-run paths can report `network-ready`.
- Changed TLS tunnel `open()` to inspect an immediately available HTTP response and return its status, while preserving non-HTTP bytes for the PPP stream through a prefixed socket wrapper.
- Updated logical edge tests for the fixed behavior and added TLS HTTP rejection/direct-PPP prefix tests.

Second run commands:

```powershell
py -B -m unittest discover -s tests
py -B tests\sandbox_vpn_connection.py
py -B tests\benchmark_tunnel_performance.py
```

Second run results:

```text
Ran 20 tests in 0.017s
OK

sandbox result: PASS
```

Second benchmark run:

| Benchmark | Frames | Elapsed | Throughput |
| --- | ---: | ---: | ---: |
| streaming_parse | 50,000 | 0.0507s | 985k frames/s |
| batch_parse | 50,000 | 0.0458s | 1.09M frames/s |
| flush_outgoing | 50,000 | 0.3048s | 164k frames/s |

Post-fix status:

- DTLS send contract risk: fixed by adding `send`.
- No-TAP readiness reporting risk: fixed at PPP engine callback level.
- TLS tunnel HTTP rejection ambiguity: improved for immediately available HTTP status responses and covered by tests.
- Remaining integration risk: real Fortinet/TAP/Wintun behavior still needs an explicit opt-in integration run because the current checks intentionally avoid credentials, adapters, route changes, and network access.
