"""Cross-platform (Linux / macOS / Windows) network diagnostics collection.

Every diagnostic is best-effort: missing tools, timeouts and crashes are
recorded in the log instead of aborting, so a later agent has maximum context.
"""
from __future__ import annotations

import json
import locale
import os
import platform
import socket
import subprocess
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple, Union

from .health import HealthResult

PING_IP = "1.1.1.1"
DNS_NAME = "www.google.com"
HTTP_PROBE_URL = "http://connectivitycheck.gstatic.com/generate_204"
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy")


@dataclass
class CommandOutput:
    returncode: Optional[int]
    stdout: str
    stderr: str
    error: Optional[str]


Runner = Callable[[Sequence[str], float], CommandOutput]
Command = Tuple[str, List[str]]


def commands_for_platform(system: str) -> List[Command]:
    if system == "Windows":
        return [
            ("interfaces", ["ipconfig", "/all"]),
            ("routes", ["route", "print"]),
            ("dns_config", ["netsh", "interface", "ip", "show", "dnsservers"]),
            ("wifi", ["netsh", "wlan", "show", "interfaces"]),
            ("proxy_config", ["netsh", "winhttp", "show", "proxy"]),
            ("ping_ip", ["ping", "-n", "3", "-w", "2000", PING_IP]),
            ("ping_name", ["ping", "-n", "3", "-w", "2000", DNS_NAME]),
            ("dns_lookup", ["nslookup", DNS_NAME]),
            ("traceroute", ["tracert", "-d", "-h", "15", "-w", "1000", PING_IP]),
            ("http_probe", ["curl.exe", "-sS", "-i", "-m", "10", HTTP_PROBE_URL]),
        ]
    if system == "Darwin":
        return [
            ("interfaces", ["ifconfig"]),
            ("routes", ["netstat", "-rn"]),
            ("default_route", ["route", "-n", "get", "default"]),
            ("dns_config", ["scutil", "--dns"]),
            ("proxy_config", ["scutil", "--proxy"]),
            ("ping_ip", ["ping", "-c", "3", "-t", "10", PING_IP]),
            ("ping_name", ["ping", "-c", "3", "-t", "10", DNS_NAME]),
            ("dns_lookup", ["nslookup", DNS_NAME]),
            ("traceroute", ["traceroute", "-n", "-m", "15", "-w", "1", PING_IP]),
            ("http_probe", ["curl", "-sS", "-i", "-m", "10", HTTP_PROBE_URL]),
        ]
    linux = [
        ("interfaces", ["ip", "addr"]),
        ("routes", ["ip", "route"]),
        ("dns_config", ["cat", "/etc/resolv.conf"]),
        ("ping_ip", ["ping", "-c", "3", "-W", "2", PING_IP]),
        ("ping_name", ["ping", "-c", "3", "-W", "2", DNS_NAME]),
        ("dns_lookup", ["nslookup", DNS_NAME]),
        ("traceroute", ["traceroute", "-n", "-m", "15", "-w", "1", PING_IP]),
        ("http_probe", ["curl", "-sS", "-i", "-m", "10", HTTP_PROBE_URL]),
    ]
    if system == "Linux":
        return linux
    # Other POSIX systems (BSDs etc.): use the portable subset.
    return [
        ("interfaces", ["ifconfig"]),
        ("routes", ["netstat", "-rn"]),
        ("ping_ip", ["ping", "-c", "3", PING_IP]),
        ("dns_lookup", ["nslookup", DNS_NAME]),
        ("traceroute", ["traceroute", "-n", "-m", "15", PING_IP]),
    ]


def run_command(argv: Sequence[str], timeout: float) -> CommandOutput:
    """Run argv (no shell) and capture output; never raises."""
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return CommandOutput(None, "", "", f"command not found: {argv[0]}")
    except subprocess.TimeoutExpired as exc:
        return CommandOutput(None, _decode(exc.stdout), _decode(exc.stderr),
                             f"timed out after {timeout:g}s")
    except Exception as exc:
        return CommandOutput(None, "", "", f"{type(exc).__name__}: {exc}")
    return CommandOutput(proc.returncode, _decode(proc.stdout), _decode(proc.stderr), None)


def _fallback_encoding(windows: Optional[bool] = None) -> str:
    """Encoding for tool output that is not valid UTF-8.

    Windows console tools (ipconfig, ping, tracert...) write in the OEM code
    page when piped; elsewhere the locale encoding is the best guess.
    """
    if windows is None:
        windows = os.name == "nt"
    return "oem" if windows else (locale.getpreferredencoding(False) or "utf-8")


def _decode(data: Union[bytes, str, None], fallback: Optional[str] = None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode(fallback or _fallback_encoding(), errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def _redact(value: str) -> str:
    """Mask credentials in proxy settings (with or without a URL scheme)."""
    scheme, sep, rest = value.partition("://")
    if not sep:
        scheme, rest = "", value
    if "@" not in rest:
        return value
    hostpart = rest.rsplit("@", 1)[1]
    return f"{scheme}{sep}***@{hostpart}"


def _bounded(fn: Callable[[], object], timeout: float) -> object:
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except Exception as exc:
            box["value"] = f"{type(exc).__name__}: {exc}"

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    return box.get("value", f"TimeoutError: no result within {timeout:g}s")


def _python_checks(timeout: float) -> dict:
    def resolve() -> object:
        infos = socket.getaddrinfo(DNS_NAME, 443, proto=socket.IPPROTO_TCP)
        return sorted({info[4][0] for info in infos})

    return {
        "hostname": socket.gethostname(),
        "getaddrinfo": {DNS_NAME: _bounded(resolve, timeout)},
        "proxy_env": {k: _redact(os.environ[k]) for k in PROXY_VARS if k in os.environ},
    }


def _health_dict(health: HealthResult) -> dict:
    return {
        "healthy": health.healthy,
        "dns_ok": health.dns_ok,
        "summary": health.summary(),
        "results": [
            {"target": str(r.target), "ok": r.ok, "latency_ms": round(r.latency_ms, 1), "error": r.error}
            for r in health.results
        ],
    }


def _unique_base(log_dir: Path, stamp: str) -> Path:
    base = log_dir / f"diag-{stamp}"
    n = 1
    while base.with_suffix(".log").exists() or base.with_suffix(".json").exists():
        base = log_dir / f"diag-{stamp}-{n}"
        n += 1
    return base


def run_diagnostics(
    health: HealthResult,
    log_dir: Union[str, Path],
    runner: Runner = run_command,
    system: Optional[str] = None,
    now: Optional[datetime] = None,
    command_timeout: float = 60.0,
) -> Path:
    """Collect diagnostics and write `<log_dir>/diag-<UTC stamp>.log` + `.json`.

    Returns the path of the human-readable .log file.
    """
    system = system or platform.system()
    now = now or datetime.now(timezone.utc)
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    commands = []
    for name, argv in commands_for_platform(system):
        try:
            out = runner(argv, command_timeout)
        except Exception as exc:
            out = CommandOutput(None, "", "", f"{type(exc).__name__}: {exc}")
        commands.append({"name": name, "argv": argv, **asdict(out)})

    report = {
        "timestamp": now.isoformat(),
        "platform": {"system": system, "release": platform.release(),
                     "python": platform.python_version()},
        "health": _health_dict(health),
        "python_checks": _python_checks(timeout=10.0),
        "commands": commands,
    }

    base = _unique_base(log_dir, now.strftime("%Y%m%dT%H%M%SZ"))
    json_path = base.with_suffix(".json")
    log_path = base.with_suffix(".log")
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log_path.write_text(_render_text(report), encoding="utf-8")
    return log_path


def _render_text(report: dict) -> str:
    lines = [
        f"Network diagnostics @ {report['timestamp']}",
        f"Platform: {report['platform']}",
        f"Health: {report['health']['summary']}",
        f"Python checks: {json.dumps(report['python_checks'])}",
        "",
    ]
    for c in report["commands"]:
        lines.append(f"===== {c['name']}: {' '.join(c['argv'])} =====")
        lines.append(f"exit code: {c['returncode']}")
        if c["error"]:
            lines.append(f"ERROR: {c['error']}")
        if c["stdout"]:
            lines.append(c["stdout"].rstrip())
        if c["stderr"]:
            lines.append("--- stderr ---")
            lines.append(c["stderr"].rstrip())
        lines.append("")
    return "\n".join(lines)
