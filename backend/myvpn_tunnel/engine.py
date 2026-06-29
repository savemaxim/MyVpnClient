"""Public boundary for the integrated MyVpn tunnel engine.

The UI bridge should import tunnel functionality from this module instead of
reaching into implementation files directly. Internal modules can still evolve
behind this small boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .dtls import DtlsUnavailable, FortinetDtlsTransport
from .fortinet import FortinetClient, summarize_config
from .ppp import FortinetPppEngine
from .tunnel import FortinetTlsTunnel

try:
    from .tap import open_packet_device as _open_packet_device
except Exception:
    _open_packet_device = None


BACKEND_NAME = "myvpn_tunnel"


@dataclass(frozen=True)
class TunnelRuntimeOptions:
    adapter_kind: str = "auto"
    prefer_dtls: bool = False
    ppp_negotiation_timeout_seconds: float = 90.0
    tunnel_idle_timeout_seconds: float = 0.0
    terminate_grace_seconds: float = 2.0


@dataclass(frozen=True)
class TunnelCallbacks:
    log: Callable[[str], None]
    on_phase: Callable[[str, str], None] | None = None
    on_stats: Callable[[dict], None] | None = None


def open_packet_adapter(kind: str, alias: str, log: Callable[[str], None]):
    if _open_packet_device is None:
        return None
    return _open_packet_device(kind, alias, log=log)


def packet_adapter_available() -> bool:
    return _open_packet_device is not None
