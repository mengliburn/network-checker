"""Optimistic, failure-tolerant invocation of an external diagnosis agent.

The network is (by definition) unhealthy when this runs, so a cloud-backed
agent may well fail. Every outcome is written next to the diagnostics so a
later agent run can see what was attempted.
"""
from __future__ import annotations

import os
import shlex
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from .diagnostics import CommandOutput, Runner, run_command

DEFAULT_AGENT_TIMEOUT = 600.0


@dataclass
class AgentOutcome:
    attempted: bool
    success: bool
    detail: str
    output_path: Optional[Path]


def build_prompt(log_path: Path) -> str:
    log_path = Path(log_path)
    return (
        "An automated internet/network health check on this machine just failed. "
        f"Diagnostics were captured in {log_path}, human readable, and "
        f"{log_path.with_suffix('.json')}, structured. Earlier check history is in "
        f"{log_path.parent / 'health.log'}. Read them, diagnose the most likely root "
        "cause - for example local link or Wi-Fi, DHCP, gateway or router, DNS, ISP, "
        "proxy, captive portal, firewall or VPN - and suggest concrete next steps. "
        "Do not change system settings."
    )


def parse_agent_command(value: Optional[str], windows: Optional[bool] = None) -> Optional[List[str]]:
    """Split a command string into argv using the platform's quoting rules.

    Raises ValueError for malformed (e.g. unbalanced-quote) POSIX commands.
    """
    if not value or not value.strip():
        return None
    if windows is None:
        windows = os.name == "nt"
    return _split_windows(value) if windows else shlex.split(value)


def _split_windows(cmdline: str) -> List[str]:
    """Split like CommandLineToArgvW / the MSVC runtime."""
    args: List[str] = []
    current: List[str] = []
    in_arg = in_quotes = False
    i, n = 0, len(cmdline)
    while i < n:
        c = cmdline[i]
        if c == "\\":
            j = i
            while j < n and cmdline[j] == "\\":
                j += 1
            count = j - i
            if j < n and cmdline[j] == '"':
                current.append("\\" * (count // 2))
                if count % 2:
                    current.append('"')
                    i = j + 1
                else:
                    i = j
            else:
                current.append("\\" * count)
                i = j
            in_arg = True
            continue
        if c == '"':
            if in_quotes and i + 1 < n and cmdline[i + 1] == '"':
                current.append('"')
                i += 2
            else:
                in_quotes = not in_quotes
                i += 1
            in_arg = True
            continue
        if c in " \t" and not in_quotes:
            if in_arg:
                args.append("".join(current))
                current, in_arg = [], False
            i += 1
            continue
        current.append(c)
        in_arg = True
        i += 1
    if in_quotes:
        raise ValueError("No closing quotation")
    if in_arg:
        args.append("".join(current))
    return args


# cmd.exe re-parses arguments passed to .bat/.cmd files ("BatBadBut"), and
# Python cannot escape them safely, so such arguments are refused instead.
_BATCH_UNSAFE = set('%^&|<>"!()\r\n')


def prepare_argv(
    argv: Sequence[str],
    windows: Optional[bool] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> List[str]:
    """Resolve the executable (Windows: honour PATHEXT so npm .cmd shims work)
    and refuse arguments that cmd.exe could misinterpret for batch files."""
    argv = list(argv)
    if windows is None:
        windows = os.name == "nt"
    if not windows or not argv:
        return argv
    resolved = which(argv[0])
    if resolved:
        argv[0] = resolved
    if argv[0].lower().endswith((".bat", ".cmd")):
        for arg in argv[1:]:
            bad = sorted(set(arg) & _BATCH_UNSAFE)
            if bad:
                raise ValueError(
                    f"refusing to pass argument containing {bad!r} to batch file {argv[0]}; "
                    "use an .exe agent or move logs to a path without these characters")
    return argv


def invoke_agent(
    log_path: Path,
    command: Optional[Sequence[str]],
    runner: Runner = run_command,
    timeout: float = DEFAULT_AGENT_TIMEOUT,
) -> AgentOutcome:
    """Run the agent command; never raises.

    `{log}`, `{json}` and `{prompt}` inside argv items are substituted.
    """
    log_path = Path(log_path)
    if not command:
        return AgentOutcome(False, False, "no agent command configured; skipped", None)

    prompt = build_prompt(log_path)
    values = {"{log}": str(log_path), "{json}": str(log_path.with_suffix(".json")),
              "{prompt}": prompt}
    argv = []
    for item in command:
        for key, val in values.items():
            item = item.replace(key, val)
        argv.append(item)

    try:
        argv = prepare_argv(argv)
        out = runner(argv, timeout)
    except Exception as exc:
        out = CommandOutput(None, "", "", f"{type(exc).__name__}: {exc}")

    success = out.error is None and out.returncode == 0
    if success:
        detail = "agent completed"
    elif out.error:
        detail = out.error
    else:
        detail = f"agent exited with code {out.returncode}"

    output_path = log_path.with_name(log_path.stem + ".agent.txt")
    text = "\n".join([
        f"Agent invocation @ {datetime.now(timezone.utc).isoformat()}",
        f"argv[0]: {argv[0]}",
        f"status: {'SUCCEEDED' if success else 'FAILED'} ({detail})",
        f"exit code: {out.returncode}",
        "--- stdout ---", out.stdout.rstrip(),
        "--- stderr ---", out.stderr.rstrip(), "",
    ])
    try:
        output_path.write_text(text, encoding="utf-8")
    except OSError as exc:
        detail += f" (could not save agent output: {exc})"
        output_path = None
    return AgentOutcome(True, success, detail, output_path)
