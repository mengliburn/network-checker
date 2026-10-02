"""Optimistically ask an AI agent to analyse a diagnostics log.

The network is (by definition) unhealthy when this runs, so the agent may
well fail to reach its backend. Every failure mode is captured in an
``*.agent.log`` file next to the diagnostics log and returned as an
:class:`AgentOutcome`; nothing here ever raises.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from .diagnostics import Runner, run_command

# GitHub Copilot CLI in non-interactive mode. Override with --agent-cmd.
DEFAULT_AGENT_COMMAND = ("copilot", "-p", "{prompt}")
# The prompt is passed as a single argv element. Linux caps one argument at
# 128 KiB (bytes) and Windows caps the whole command line at ~32k chars, so
# embed a bounded excerpt (UTF-8 bytes >= chars) and point at the full file.
MAX_LOG_BYTES_IN_PROMPT = 24_000

PROMPT_TEMPLATE = """\
An automated internet/network health check on this machine just failed.
Diagnostics were collected into: {log_file}

Please analyse the diagnostics below, identify the most likely root cause
(e.g. no link/IP address, missing default route, DNS failure, upstream/ISP
outage, firewall), and suggest concrete steps to fix it.

----- BEGIN DIAGNOSTICS -----
{log_text}
----- END DIAGNOSTICS -----
"""


@dataclass
class AgentOutcome:
    invoked: bool
    success: bool
    message: str
    output_path: Optional[Path] = None


def _truncate_bytes(text: str, limit: int) -> str:
    data = text.encode("utf-8")
    if len(data) <= limit:
        return text
    half = limit // 2
    # errors="ignore" drops any multi-byte character split at the cut points.
    head = data[:half].decode("utf-8", errors="ignore")
    tail = data[-half:].decode("utf-8", errors="ignore")
    omitted = len(data) - 2 * half
    return f"{head}\n\n[... {omitted} bytes truncated; see the full log file ...]\n\n{tail}"


def build_prompt(log_path: Path, log_text: str) -> str:
    log_text = _truncate_bytes(log_text, MAX_LOG_BYTES_IN_PROMPT)
    # str.replace (not str.format) so braces in log content are harmless.
    return PROMPT_TEMPLATE.replace("{log_file}", str(log_path)).replace("{log_text}", log_text)


def _substitute(arg: str, values: dict) -> str:
    # Single pass so substituted values are never re-scanned for placeholders.
    out, i = [], 0
    while i < len(arg):
        for key, value in values.items():
            if arg.startswith(key, i):
                out.append(value)
                i += len(key)
                break
        else:
            out.append(arg[i])
            i += 1
    return "".join(out)


def invoke_agent(
    log_path: Path,
    command: Sequence[str] = DEFAULT_AGENT_COMMAND,
    runner: Runner = run_command,
    timeout: float = 300.0,
) -> AgentOutcome:
    """Run the agent ``command`` (argv list, no shell) for ``log_path``.

    ``{log_file}`` and ``{prompt}`` placeholders inside any argument are
    replaced with the log path and a ready-made analysis prompt.
    """
    if not command:
        return AgentOutcome(False, False, "agent invocation disabled")

    log_path = Path(log_path)
    output_path = log_path.with_suffix(".agent.log")
    try:
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log_text = f"[could not read diagnostics log: {exc}]"
    values = {"{log_file}": str(log_path), "{prompt}": build_prompt(log_path, log_text)}
    argv = [_substitute(arg, values) for arg in command]

    invoked, success, output = False, False, ""
    try:
        result = runner(argv, timeout)
        invoked = True
        output = result.output
        if result.timed_out:
            message = f"agent timed out after {timeout}s"
        elif result.returncode == 0:
            success, message = True, "agent completed successfully"
        else:
            message = f"agent failed with exit code {result.returncode} (possibly due to network conditions)"
    except FileNotFoundError:
        message = f"agent executable not found: {argv[0]}"
    except Exception as exc:  # noqa: BLE001 - must never crash the monitor
        message = f"agent invocation error: {type(exc).__name__}: {exc}"

    try:
        output_path.write_text(
            f"command: {command[0]} (template: {list(command)})\nstatus: {message}\n\n{output}",
            encoding="utf-8",
        )
    except OSError as exc:
        message += f" (could not write {output_path}: {exc})"
        output_path = None
    return AgentOutcome(invoked, success, message, output_path)
