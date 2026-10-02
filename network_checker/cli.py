"""Command line entry point: python -m network_checker [options]."""
from __future__ import annotations

import argparse
import os
import signal
import sys
from typing import List, Optional

from .agent import DEFAULT_AGENT_TIMEOUT, invoke_agent, parse_agent_command
from .diagnostics import run_diagnostics
from .health import DEFAULT_TARGETS, Target, check_health
from .monitor import Monitor

AGENT_ENV = "NETWORK_CHECKER_AGENT_CMD"

# Signals that should stop the monitor through the same clean path as Ctrl+C
# (which also kills any running diagnostic/agent process tree).
TERMINATION_SIGNALS = tuple(
    getattr(signal, name) for name in ("SIGTERM", "SIGHUP", "SIGBREAK") if hasattr(signal, name)
)


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt(f"received signal {signum}")


def install_signal_handlers() -> dict:
    """Install handlers; returns the previous ones for restore_signal_handlers."""
    previous = {}
    for sig in TERMINATION_SIGNALS:
        try:
            previous[sig] = signal.signal(sig, _raise_interrupt)
        except (ValueError, OSError):  # not main thread / unsupported
            pass
    return previous


def restore_signal_handlers(previous: dict) -> None:
    for sig, handler in previous.items():
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError, TypeError):
            pass


def parse_target(value: str) -> Target:
    value = value.strip()
    if not value:
        raise argparse.ArgumentTypeError("empty target")
    if value.startswith("["):  # [ipv6]:port or [ipv6]
        host, _, rest = value[1:].partition("]")
        port_text = rest[1:] if rest.startswith(":") else "443"
    elif value.count(":") == 1:
        host, port_text = value.split(":")
    else:  # hostname, IPv4, or bare IPv6
        host, port_text = value, "443"
    try:
        port = int(port_text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port in {value!r}") from None
    if not host or not 0 < port < 65536:
        raise argparse.ArgumentTypeError(f"invalid target {value!r}")
    return Target(host, port)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_checker",
        description="Ping-like internet health check that captures diagnostics "
                    "and optionally invokes an agent when the network is down.")
    p.add_argument("--once", action="store_true",
                   help="run a single check; exit 0 if healthy, 1 if not")
    p.add_argument("--interval", type=float, default=60.0, help="seconds between checks (default 60)")
    p.add_argument("--timeout", type=float, default=5.0, help="per-check timeout in seconds (default 5)")
    p.add_argument("--cooldown", type=float, default=900.0,
                   help="minimum seconds between diagnostics during one outage (default 900)")
    p.add_argument("--log-dir", default="logs", help="directory for logs (default ./logs)")
    p.add_argument("--target", action="append", type=parse_target, metavar="HOST[:PORT]",
                   help="extra TCP endpoint to probe (repeatable); added to the built-in "
                        "content-verified connectivity checks")
    p.add_argument("--no-default-targets", action="store_true",
                   help="probe only --target endpoints (TCP connect only: captive portals "
                        "can then look healthy)")
    p.add_argument("--agent-cmd", default=os.environ.get(AGENT_ENV),
                   help="agent command run on failure; {log}, {json}, {prompt} are substituted "
                        f"(default: ${AGENT_ENV}; omit to only collect diagnostics)")
    p.add_argument("--agent-timeout", type=float, default=DEFAULT_AGENT_TIMEOUT,
                   help="seconds before the agent is abandoned (default 600)")
    p.add_argument("--quiet", action="store_true", help="do not echo status lines to stdout")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_default_targets:
        if not args.target:
            parser.error("--no-default-targets requires at least one --target")
        targets = list(args.target)
    else:
        targets = list(DEFAULT_TARGETS) + list(args.target or [])
    try:
        agent_argv = parse_agent_command(args.agent_cmd)
    except ValueError as exc:
        parser.error(f"invalid agent command ({AGENT_ENV} / --agent-cmd): {exc}")

    agent = None
    if agent_argv:
        agent = lambda log_path: invoke_agent(log_path, agent_argv, timeout=args.agent_timeout)

    monitor = Monitor(
        check=lambda: check_health(targets, timeout=args.timeout),
        diagnose=lambda health: run_diagnostics(health, args.log_dir),
        agent=agent,
        log_dir=args.log_dir,
        cooldown=args.cooldown,
        echo=(lambda line: None) if args.quiet else (lambda line: print(line, flush=True)),
    )
    previous_handlers = install_signal_handlers()
    try:
        if args.once:
            return 0 if monitor.run_once().healthy else 1
        monitor.run_forever(args.interval)
    except KeyboardInterrupt:
        return 0
    finally:
        restore_signal_handlers(previous_handlers)
    return 0


if __name__ == "__main__":
    sys.exit(main())
