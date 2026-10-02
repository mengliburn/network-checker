"""Command line interface: ``python -m network_checker``."""

from __future__ import annotations

import argparse
import functools
import logging
import shlex
import sys
from pathlib import Path
from typing import List, Optional

from .agent import DEFAULT_AGENT_COMMAND, invoke_agent
from .diagnostics import default_commands, run_diagnostics
from .health import DEFAULT_TARGETS, Target, check_health
from .monitor import Monitor


def _target(value: str) -> Target:
    try:
        return Target.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _positive(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be > 0, got {value}")
    return number


def _agent_cmd(value: str) -> List[str]:
    return shlex.split(value)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="network-checker",
        description="Ping-like internet health check. On failure, collect diagnostics "
        "into a log and optimistically ask an AI agent to analyse them.",
    )
    parser.add_argument("-t", "--target", dest="targets", action="append", type=_target, metavar="HOST[:PORT]",
                        help="endpoint to probe via TCP (repeatable; default: Cloudflare, Google, Yahoo)")
    parser.add_argument("--once", action="store_true",
                        help="run a single check and exit (0 = healthy, 1 = unhealthy)")
    parser.add_argument("--interval", type=_positive, default=60.0, help="seconds between checks (default 60)")
    parser.add_argument("--timeout", type=_positive, default=3.0, help="per-target connect timeout (default 3)")
    parser.add_argument("--cooldown", type=float, default=900.0,
                        help="min seconds between diagnostics during one outage (default 900)")
    parser.add_argument("--log-dir", type=Path, default=Path("logs"), help="where logs are written (default ./logs)")
    parser.add_argument("--command-timeout", type=_positive, default=30.0,
                        help="timeout per diagnostic command (default 30)")
    agent = parser.add_mutually_exclusive_group()
    agent.add_argument("--agent-cmd", type=_agent_cmd, default=list(DEFAULT_AGENT_COMMAND),
                       help="agent command line; {prompt} and {log_file} are substituted "
                       f"(default: {shlex.join(DEFAULT_AGENT_COMMAND)!r})")
    agent.add_argument("--no-agent", dest="agent_cmd", action="store_const", const=[],
                       help="do not invoke an agent")
    parser.add_argument("--agent-timeout", type=_positive, default=300.0, help="agent timeout (default 300)")
    parser.add_argument("-q", "--quiet", action="store_true", help="only log warnings and errors to the console")
    args = parser.parse_args(argv)
    if not args.targets:
        args.targets = list(DEFAULT_TARGETS)
    return args


def _setup_logging(log_dir: Path, quiet: bool) -> None:
    logger = logging.getLogger("network_checker")
    logger.setLevel(logging.INFO)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING if quiet else logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "network-checker.log", encoding="utf-8")
    except OSError as exc:
        logger.warning("cannot write monitor log in %s: %s", log_dir, exc)
    else:
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    logger.propagate = False


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    _setup_logging(args.log_dir, args.quiet)

    monitor = Monitor(
        check=functools.partial(check_health, args.targets, args.timeout),
        diagnose=functools.partial(
            run_diagnostics,
            log_dir=args.log_dir,
            commands=default_commands(),
            command_timeout=args.command_timeout,
        ),
        agent=functools.partial(invoke_agent, command=args.agent_cmd, timeout=args.agent_timeout)
        if args.agent_cmd
        else None,
        cooldown=args.cooldown,
    )
    if args.once:
        return 0 if monitor.run_once().healthy else 1
    try:
        monitor.run_forever(args.interval)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
