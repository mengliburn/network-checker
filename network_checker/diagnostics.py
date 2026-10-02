"""Collect network diagnostics into a log file for later (agent) analysis.

Every diagnostic is best effort: missing tools, timeouts and unexpected
errors are written to the log instead of aborting the collection. Sections
are flushed as they complete so a partial log survives a crash.
"""

from __future__ import annotations

import datetime as dt
import platform as _platform
import socket
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence

from .health import HealthResult

DEFAULT_DNS_HOSTS = ("www.google.com", "www.cloudflare.com", "www.yahoo.com")


@dataclass(frozen=True)
class DiagnosticCommand:
    name: str
    argv: List[str]


@dataclass
class CommandResult:
    returncode: Optional[int]
    output: str
    timed_out: bool = False


Runner = Callable[[Sequence[str], float], CommandResult]
Resolver = Callable[..., list]


def run_command(argv: Sequence[str], timeout: float) -> CommandResult:
    """Run ``argv`` (never through a shell). Raises FileNotFoundError if missing."""
    try:
        proc = subprocess.run(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            text=True,
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.output or ""
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        return CommandResult(returncode=None, output=out, timed_out=True)
    return CommandResult(returncode=proc.returncode, output=proc.stdout or "")


def default_commands(platform: Optional[str] = None) -> List[DiagnosticCommand]:
    platform = platform or sys.platform
    if platform.startswith("win"):
        return [
            DiagnosticCommand("interfaces", ["ipconfig", "/all"]),
            DiagnosticCommand("routes", ["route", "print"]),
            DiagnosticCommand("dns lookup", ["nslookup", "www.google.com"]),
            DiagnosticCommand("ping 8.8.8.8", ["ping", "-n", "3", "-w", "2000", "8.8.8.8"]),
            DiagnosticCommand("ping 1.1.1.1", ["ping", "-n", "3", "-w", "2000", "1.1.1.1"]),
            DiagnosticCommand("traceroute 8.8.8.8", ["tracert", "-d", "-h", "15", "-w", "2000", "8.8.8.8"]),
        ]
    if platform == "darwin":
        return [
            DiagnosticCommand("interfaces", ["ifconfig"]),
            DiagnosticCommand("routes", ["netstat", "-rn"]),
            DiagnosticCommand("dns config", ["scutil", "--dns"]),
            DiagnosticCommand("ping 8.8.8.8", ["ping", "-c", "3", "-t", "5", "8.8.8.8"]),
            DiagnosticCommand("ping 1.1.1.1", ["ping", "-c", "3", "-t", "5", "1.1.1.1"]),
            DiagnosticCommand("traceroute 8.8.8.8", ["traceroute", "-n", "-w", "2", "-m", "15", "8.8.8.8"]),
        ]
    return [
        DiagnosticCommand("interfaces", ["ip", "addr"]),
        DiagnosticCommand("routes", ["ip", "route"]),
        DiagnosticCommand("dns config (/etc/resolv.conf)", ["cat", "/etc/resolv.conf"]),
        DiagnosticCommand("ping 8.8.8.8", ["ping", "-c", "3", "-W", "2", "8.8.8.8"]),
        DiagnosticCommand("ping 1.1.1.1", ["ping", "-c", "3", "-W", "2", "1.1.1.1"]),
        DiagnosticCommand("traceroute 8.8.8.8", ["traceroute", "-n", "-w", "2", "-m", "15", "8.8.8.8"]),
    ]


def _create_log_file(log_dir: Path, timestamp: dt.datetime):
    """Atomically create a new, uniquely named log file (never overwrites)."""
    stem = f"diagnostics-{timestamp.strftime('%Y%m%dT%H%M%SZ')}"
    counter = 0
    while True:
        path = log_dir / (f"{stem}.log" if counter == 0 else f"{stem}-{counter}.log")
        try:
            return path, open(path, "x", encoding="utf-8")
        except FileExistsError:
            counter += 1


def _describe_command(cmd: DiagnosticCommand, runner: Runner, timeout: float) -> str:
    try:
        result = runner(cmd.argv, timeout)
    except FileNotFoundError:
        return f"[command not available on this system: {cmd.argv[0]}]"
    except Exception as exc:  # noqa: BLE001 - diagnostics must never abort
        return f"[error running command: {type(exc).__name__}: {exc}]"
    lines = []
    if result.timed_out:
        lines.append(f"[timed out after {timeout}s]")
    else:
        lines.append(f"[exit code {result.returncode}]")
    lines.append(result.output.rstrip())
    return "\n".join(lines)


def _describe_dns(host: str, resolver: Resolver, timeout: float) -> str:
    # getaddrinfo has no timeout of its own and tends to hang exactly when the
    # network is broken, so run it in a daemon thread and abandon it if slow.
    box: dict = {}

    def target() -> None:
        try:
            box["infos"] = resolver(host, 443)
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=target, name=f"dns-{host}", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return f"{host}: FAILED (timed out after {timeout}s)"
    if "error" in box:
        exc = box["error"]
        return f"{host}: FAILED ({type(exc).__name__}: {exc})"
    infos = box.get("infos") or []
    addresses = sorted({info[4][0] for info in infos})
    return f"{host}: {', '.join(addresses) or '(no addresses)'}"


def run_diagnostics(
    health: HealthResult,
    log_dir: Path,
    commands: Optional[Iterable[DiagnosticCommand]] = None,
    runner: Runner = run_command,
    resolver: Resolver = socket.getaddrinfo,
    dns_hosts: Iterable[str] = DEFAULT_DNS_HOSTS,
    command_timeout: float = 30.0,
    dns_timeout: float = 10.0,
    now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
) -> Path:
    """Run diagnostics and write them to a new log file. Returns its path.

    Individual diagnostics never raise; failures are recorded in the log.
    An ``OSError`` is raised only if the log itself cannot be written.
    """
    commands = default_commands() if commands is None else list(commands)
    timestamp = now()
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    path, log = _create_log_file(log_dir, timestamp)

    with log:

        def section(title: str, body: str) -> None:
            log.write(f"===== {title} =====\n{body}\n\n")
            log.flush()

        section(
            "network health check failure",
            f"time: {timestamp.isoformat()}\n"
            f"host: {socket.gethostname()} ({_platform.platform()})\n\n"
            f"{health.summary()}",
        )
        section("dns resolution", "\n".join(_describe_dns(h, resolver, dns_timeout) for h in dns_hosts))
        for cmd in commands:
            section(f"{cmd.name}: {' '.join(cmd.argv)}", _describe_command(cmd, runner, command_timeout))
    return path
