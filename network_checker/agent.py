"""Optimistic, failure-tolerant invocation of an external diagnosis agent.

The network is (by definition) unhealthy when this runs, so a cloud-backed
agent may well fail. Every outcome is written next to the diagnostics so a
later agent run can see what was attempted.
"""
from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

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
        f"Diagnostics were captured in {log_path} (human readable) and "
        f"{log_path.with_suffix('.json')} (structured). Earlier check history is in "
        f"{log_path.parent / 'health.log'}. Read them, diagnose the most likely root "
        "cause (e.g. local link/Wi-Fi, DHCP, gateway/router, DNS, ISP, proxy, "
        "captive portal, firewall/VPN) and suggest concrete next steps. "
        "Do not change system settings."
    )


def parse_agent_command(value: Optional[str], windows: Optional[bool] = None) -> Optional[List[str]]:
    """Split a command string into argv using the platform's quoting rules."""
    if not value or not value.strip():
        return None
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        return shlex.split(value)
    # Windows: keep backslashes literal; only double quotes group words.
    argv = []
    for token in shlex.split(value, posix=False):
        if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
            token = token[1:-1]
        argv.append(token)
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
