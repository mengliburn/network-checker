"""Ping-like connectivity checks against reliable external providers.

ICMP ping usually needs elevated privileges, so we "ping" by opening a TCP
connection to well-known, highly available endpoints. The network is
considered healthy if *any* target is reachable, so a single provider outage
does not trigger a false alarm.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional

Connector = Callable[..., object]


@dataclass(frozen=True)
class Target:
    host: str
    port: int = 443

    @classmethod
    def parse(cls, spec: str) -> "Target":
        """Parse ``host``, ``host:port``, ``[ipv6]``, ``[ipv6]:port`` or bare ``ipv6``."""
        text = spec.strip()
        if text.startswith("["):
            end = text.find("]")
            if end == -1:
                raise ValueError(f"invalid target {spec!r}: missing ']'")
            host, rest = text[1:end], text[end + 1 :]
            if rest and not rest.startswith(":"):
                raise ValueError(f"invalid target {spec!r}: expected ':' after ']'")
            port = rest[1:] if rest else "443"
        elif text.count(":") > 1:
            host, port = text, "443"  # bare IPv6 address, no port
        elif ":" in text:
            host, _, port = text.partition(":")
        else:
            host, port = text, "443"
        if not host:
            raise ValueError(f"invalid target {spec!r}: missing host")
        try:
            port_num = int(port)
        except ValueError:
            raise ValueError(f"invalid target {spec!r}: port must be a number") from None
        if not 0 < port_num < 65536:
            raise ValueError(f"invalid target {spec!r}: port out of range")
        return cls(host, port_num)

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


DEFAULT_TARGETS = (
    Target("1.1.1.1", 443),  # Cloudflare (IP: works even if DNS is broken)
    Target("8.8.8.8", 53),  # Google Public DNS (IP)
    Target("www.google.com", 443),  # needs DNS
    Target("www.yahoo.com", 443),  # needs DNS
)


@dataclass
class ProbeResult:
    target: Target
    ok: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class HealthResult:
    probes: List[ProbeResult] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return any(p.ok for p in self.probes)

    def summary(self) -> str:
        lines = []
        for p in self.probes:
            if p.ok:
                lines.append(f"OK   {p.target} ({p.latency_ms:.1f} ms)")
            else:
                lines.append(f"FAIL {p.target} ({p.error})")
        return "\n".join(lines)


def probe_target(
    target: Target,
    timeout: float = 3.0,
    connector: Connector = socket.create_connection,
) -> ProbeResult:
    start = time.monotonic()
    try:
        sock = connector((target.host, target.port), timeout)
    except (OSError, ValueError) as exc:  # socket.timeout/gaierror are OSErrors
        return ProbeResult(target, ok=False, error=f"{type(exc).__name__}: {exc}")
    latency_ms = (time.monotonic() - start) * 1000
    try:
        sock.close()
    except OSError:
        pass
    return ProbeResult(target, ok=True, latency_ms=latency_ms)


def check_health(
    targets: Iterable[Target] = DEFAULT_TARGETS,
    timeout: float = 3.0,
    connector: Connector = socket.create_connection,
) -> HealthResult:
    return HealthResult([probe_target(t, timeout, connector) for t in targets])
