"""Lightweight "ping-like" internet health check.

ICMP ping usually requires elevated privileges, so reachability is checked by
opening a TCP connection to highly available public endpoints instead.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional

Connector = Callable[[str, int, float], None]


@dataclass(frozen=True)
class Target:
    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


DEFAULT_TARGETS = (
    Target("1.1.1.1", 443),       # Cloudflare (anycast, raw IP: no DNS needed)
    Target("8.8.8.8", 443),       # Google Public DNS (anycast)
    Target("www.google.com", 443),  # exercises DNS resolution too
)


@dataclass
class TargetResult:
    target: Target
    ok: bool
    latency_ms: float
    error: Optional[str] = None


@dataclass
class HealthResult:
    results: List[TargetResult] = field(default_factory=list)

    @property
    def dns_ok(self) -> Optional[bool]:
        """True/False if any hostname target was checked, otherwise None."""
        named = [r for r in self.results if not _is_ip(r.target.host)]
        if not named:
            return None
        return any(r.ok for r in named)

    @property
    def healthy(self) -> bool:
        return any(r.ok for r in self.results) and self.dns_ok is not False

    def summary(self) -> str:
        parts = []
        for r in self.results:
            if r.ok:
                parts.append(f"{r.target} OK ({r.latency_ms:.0f} ms)")
            else:
                parts.append(f"{r.target} FAIL ({r.error})")
        if self.dns_ok is False:
            parts.append("DNS resolution FAILED for all hostname targets")
        return "; ".join(parts) if parts else "no targets checked"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def tcp_connect(host: str, port: int, timeout: float) -> None:
    with socket.create_connection((host, port), timeout=timeout):
        pass


def _probe(target: Target, connector: Connector, timeout: float) -> TargetResult:
    start = time.monotonic()
    try:
        connector(target.host, target.port, timeout)
    except Exception as exc:  # any failure means this target is unreachable
        error = f"{type(exc).__name__}: {exc}"
        return TargetResult(target, False, (time.monotonic() - start) * 1000, error)
    return TargetResult(target, True, (time.monotonic() - start) * 1000)


def check_health(
    targets: Iterable[Target] = DEFAULT_TARGETS,
    connector: Connector = tcp_connect,
    timeout: float = 5.0,
) -> HealthResult:
    """Probe all targets concurrently, bounded by an overall deadline.

    socket timeouts do not cover DNS resolution, so each probe runs in a daemon
    thread; probes still running at the deadline are reported as timeouts and
    cannot block interpreter shutdown.
    """
    targets = list(targets)
    slots: List[Optional[TargetResult]] = [None] * len(targets)

    def run(i: int, target: Target) -> None:
        slots[i] = _probe(target, connector, timeout)

    threads = [
        threading.Thread(target=run, args=(i, t), daemon=True)
        for i, t in enumerate(targets)
    ]
    for t in threads:
        t.start()
    # small grace period beyond the per-socket timeout for scheduling overhead
    deadline = time.monotonic() + timeout + 1.0
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))

    result = HealthResult()
    for i, target in enumerate(targets):
        slot = slots[i]
        if slot is None:
            slot = TargetResult(
                target, False, timeout * 1000,
                f"TimeoutError: no response within {timeout:g}s (incl. DNS)",
            )
        result.results.append(slot)
    return result
