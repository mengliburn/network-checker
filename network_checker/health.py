"""Lightweight "ping-like" internet health check (Linux, macOS, Windows).

ICMP ping needs elevated privileges on some platforms, so the check instead
uses the same plain-HTTP connectivity endpoints the operating systems use for
captive-portal detection (Android/Chrome, Apple, Windows). Their response
content is verified, so a captive portal or intercepting proxy that answers
every connection is *not* mistaken for working internet, and no local CA
certificate store is required. Raw-IP TCP probes to anycast DNS providers are
kept as supporting signals that help localise a failure.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional

MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    path: Optional[str] = None           # set => HTTP GET probe, else TCP connect
    expect_status: Optional[int] = None
    expect_body: Optional[str] = None

    def __str__(self) -> str:
        if self.path:
            return f"http://{self.host}:{self.port}{self.path}"
        return f"{self.host}:{self.port}"


Connector = Callable[[Target, float], None]

DEFAULT_TARGETS = (
    # Content-verified connectivity checks (hostname => also exercises DNS)
    Target("connectivitycheck.gstatic.com", 80, "/generate_204", 204),
    Target("captive.apple.com", 80, "/hotspot-detect.html", 200, "Success"),
    Target("www.msftconnecttest.com", 80, "/connecttest.txt", 200, "Microsoft Connect Test"),
    # Supporting raw-IP reachability (no DNS needed): Cloudflare, Google DNS
    Target("1.1.1.1", 443),
    Target("8.8.8.8", 443),
)


class UnexpectedResponse(Exception):
    """The endpoint answered, but not with the expected content."""


@dataclass
class TargetResult:
    target: Target
    ok: bool
    latency_ms: float
    error: Optional[str] = None
    dns_failure: bool = False
    unexpected_response: bool = False


@dataclass
class HealthResult:
    results: List[TargetResult] = field(default_factory=list)

    @property
    def dns_ok(self) -> Optional[bool]:
        """True if a hostname target succeeded, False if every hostname target
        failed specifically at name resolution, otherwise None (unknown)."""
        named = [r for r in self.results if not _is_ip(r.target.host)]
        if not named:
            return None
        if any(r.ok for r in named):
            return True
        if all(r.dns_failure for r in named):
            return False
        return None

    @property
    def healthy(self) -> bool:
        verified = [r for r in self.results if r.target.path]
        pool = verified or self.results
        return any(r.ok for r in pool) and self.dns_ok is not False

    def summary(self) -> str:
        parts = []
        for r in self.results:
            if r.ok:
                parts.append(f"{r.target} OK ({r.latency_ms:.0f} ms)")
            else:
                parts.append(f"{r.target} FAIL ({r.error})")
        if self.dns_ok is False:
            parts.append("DNS resolution FAILED for all hostname targets")
        if any(r.unexpected_response for r in self.results):
            parts.append("unexpected HTTP response: possible captive portal or intercepting proxy")
        return "; ".join(parts) if parts else "no targets checked"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _resolve(host: str, port: int, timeout: float) -> list:
    """getaddrinfo bounded by timeout (it otherwise ignores socket timeouts)."""
    box: dict = {}

    def run() -> None:
        try:
            box["infos"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except Exception as exc:
            box["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise socket.gaierror(f"DNS resolution of {host} timed out after {timeout:g}s")
    if "error" in box:
        raise box["error"]
    if not box["infos"]:
        raise socket.gaierror(f"no addresses for {host}")
    return box["infos"]


def _connect_addr(family: int, addr: tuple, timeout: float) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(addr)
    except BaseException:
        sock.close()
        raise
    return sock


def _open(host: str, port: int, timeout: float) -> socket.socket:
    """Resolve and connect within one shared deadline.

    IPv4 is tried first and each address gets a fair share of the remaining
    time, so a host with broken IPv6 cannot burn the whole budget.
    """
    deadline = time.monotonic() + timeout
    infos = _resolve(host, port, timeout)
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    last_error: Optional[BaseException] = None
    for index, (family, _type, _proto, _canon, addr) in enumerate(infos):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            return _connect_addr(family, addr, remaining / (len(infos) - index))
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise socket.timeout(f"no address of {host} connected within {timeout:g}s")


def tcp_connect(host: str, port: int, timeout: float) -> None:
    _open(host, port, timeout).close()


def _http_get(target: Target, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    host_header = target.host if target.port == 80 else f"{target.host}:{target.port}"
    request = (
        f"GET {target.path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "User-Agent: network-checker\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    with _open(target.host, target.port, timeout) as sock:
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        sock.sendall(request)
        data = b""
        while len(data) < MAX_RESPONSE_BYTES:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
            if _response_complete(data):
                break
    _verify_response(target, data)


def _split(data: bytes):
    head, sep, body = data.partition(b"\r\n\r\n")
    return head, sep, body


def _response_complete(data: bytes) -> bool:
    head, sep, body = _split(data)
    if not sep:
        return False
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) >= 2 and parts[1] in ("204", "304"):
        return True
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "content-length" and value.strip().isdigit():
            return len(body) >= int(value.strip())
    return False


def _verify_response(target: Target, data: bytes) -> None:
    head, _sep, body = _split(data)
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise UnexpectedResponse(f"not an HTTP response: {lines[0][:80]!r}")
    status = int(parts[1])
    location = ""
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "location":
            location = f" (Location: {value.strip()})"
    if target.expect_status is not None and status != target.expect_status:
        raise UnexpectedResponse(f"HTTP {status}, expected {target.expect_status}{location}")
    if target.expect_body is not None:
        text = body.decode("utf-8", errors="replace")
        if target.expect_body not in text:
            raise UnexpectedResponse(
                f"HTTP {status} body did not contain {target.expect_body!r}: {text[:80]!r}")


def probe_target(target: Target, timeout: float) -> None:
    """Default connector: HTTP content check if target.path, else TCP connect."""
    if target.path:
        _http_get(target, timeout)
    else:
        tcp_connect(target.host, target.port, timeout)


def _probe(target: Target, connector: Connector, timeout: float) -> TargetResult:
    start = time.monotonic()
    try:
        connector(target, timeout)
    except Exception as exc:  # any failure means this target is unreachable
        return TargetResult(
            target, False, (time.monotonic() - start) * 1000, f"{type(exc).__name__}: {exc}",
            dns_failure=isinstance(exc, (socket.gaierror, socket.herror)),
            unexpected_response=isinstance(exc, UnexpectedResponse),
        )
    return TargetResult(target, True, (time.monotonic() - start) * 1000)


def check_health(
    targets: Iterable[Target] = DEFAULT_TARGETS,
    connector: Connector = probe_target,
    timeout: float = 5.0,
) -> HealthResult:
    """Probe all targets concurrently, bounded by an overall deadline.

    Probes run in daemon threads; any still running at the deadline are
    reported as timeouts and cannot block interpreter shutdown.
    """
    targets = list(targets)
    slots: List[Optional[TargetResult]] = [None] * len(targets)

    def run(i: int, target: Target) -> None:
        slots[i] = _probe(target, connector, timeout)

    threads = [threading.Thread(target=run, args=(i, t), daemon=True)
               for i, t in enumerate(targets)]
    for t in threads:
        t.start()
    # small grace period beyond the per-probe timeout for scheduling overhead
    deadline = time.monotonic() + timeout + 1.0
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))

    result = HealthResult()
    for i, target in enumerate(targets):
        slot = slots[i]
        if slot is None:
            slot = TargetResult(target, False, timeout * 1000,
                                f"TimeoutError: no response within {timeout:g}s")
        result.results.append(slot)
    return result
