"""Lightweight myvpn_tunnel PPP performance checks.

Run from the repository root:

    py -B tests\benchmark_tunnel_performance.py

The script avoids real network and adapter access. It benchmarks hot paths that
matter for tunnel throughput: Fortinet PPP frame parsing and outgoing frame
wrapping/sending. The outgoing benchmark can run in pre-network mode
(negotiation/control behavior) and network-ready mode (fast data path).
"""

from __future__ import annotations

import json
import sys
import struct
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from myvpn_tunnel.ppp import FortinetPppEngine, PPP_IP, build_ppp_frame


FRAME_COUNT = 50_000
PAYLOAD_SIZE = 128


def fortinet_frame(proto: int, payload: bytes) -> bytes:
    ppp_frame = build_ppp_frame(proto, payload)
    return struct.pack(">HHH", len(ppp_frame) + 6, 0x5050, len(ppp_frame)) + ppp_frame


def mark_network_ready(engine: FortinetPppEngine) -> None:
    engine.state.lcp_ack_sent = True
    engine.state.lcp_ack_received = True
    engine.state.ipcp_ack_sent = True
    engine.state.ipcp_ack_received = True
    engine.state.phase = "network-ready"


class CountingSocket:
    def __init__(self) -> None:
        self.calls = 0
        self.bytes = 0

    def send(self, data) -> int:
        length = len(data)
        self.calls += 1
        self.bytes += length
        return length


def benchmark_batch_parse(frame: bytes) -> dict:
    engine = FortinetPppEngine(CountingSocket(), log=lambda _message: None)
    engine.rx_buffer.extend(frame * FRAME_COUNT)
    start = time.perf_counter()
    engine.process_rx_buffer()
    elapsed = time.perf_counter() - start
    return {
        "name": "batch_parse",
        "frames": FRAME_COUNT,
        "payloadBytes": PAYLOAD_SIZE,
        "elapsedSeconds": elapsed,
        "framesPerSecond": FRAME_COUNT / elapsed,
        "rxPackets": engine.state.rx_packets,
    }


def benchmark_streaming_parse(frame: bytes) -> dict:
    engine = FortinetPppEngine(CountingSocket(), log=lambda _message: None)
    start = time.perf_counter()
    for _ in range(FRAME_COUNT):
        engine.rx_buffer.extend(frame)
        engine.process_rx_buffer()
    elapsed = time.perf_counter() - start
    return {
        "name": "streaming_parse",
        "frames": FRAME_COUNT,
        "payloadBytes": PAYLOAD_SIZE,
        "elapsedSeconds": elapsed,
        "framesPerSecond": FRAME_COUNT / elapsed,
        "rxPackets": engine.state.rx_packets,
    }


def benchmark_flush_outgoing(payload: bytes, *, fast_data_path: bool, network_ready: bool) -> dict:
    sock = CountingSocket()
    engine = FortinetPppEngine(sock, log=lambda _message: None, fast_data_path=fast_data_path)
    if network_ready:
        mark_network_ready(engine)
    for _ in range(FRAME_COUNT):
        engine.outgoing.append((PPP_IP, payload))
    start = time.perf_counter()
    while engine.outgoing:
        engine.flush_outgoing()
    elapsed = time.perf_counter() - start
    return {
        "name": "flush_outgoing",
        "fastDataPath": fast_data_path,
        "networkReady": network_ready,
        "frames": FRAME_COUNT,
        "payloadBytes": PAYLOAD_SIZE,
        "elapsedSeconds": elapsed,
        "framesPerSecond": FRAME_COUNT / elapsed,
        "sendCalls": sock.calls,
        "sentBytes": sock.bytes,
        "txPackets": engine.state.tx_packets,
        "txSocketWrites": engine.tx_socket_writes,
        "txCoalescedFrames": engine.tx_coalesced_frames,
    }


def main() -> int:
    payload = b"E" + b"\x00" * (PAYLOAD_SIZE - 1)
    frame = fortinet_frame(PPP_IP, payload)
    results = [
        benchmark_streaming_parse(frame),
        benchmark_batch_parse(frame),
        benchmark_flush_outgoing(payload, fast_data_path=False, network_ready=True),
        benchmark_flush_outgoing(payload, fast_data_path=True, network_ready=False),
        benchmark_flush_outgoing(payload, fast_data_path=True, network_ready=True),
    ]
    print(json.dumps({"frameCount": FRAME_COUNT, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
