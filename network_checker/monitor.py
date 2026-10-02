"""Periodic health-check loop: check -> (on failure) diagnose -> ask agent."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from .agent import AgentOutcome
from .health import HealthResult

log = logging.getLogger("network_checker")


@dataclass
class CycleResult:
    healthy: bool
    health: Optional[HealthResult] = None
    log_path: Optional[Path] = None
    agent_outcome: Optional[AgentOutcome] = None
    error: Optional[str] = None


class Monitor:
    """Runs health checks; on failure collects diagnostics and invokes an agent.

    While an outage persists, diagnostics are re-collected at most once per
    ``cooldown`` seconds. After recovery, the next failure is diagnosed
    immediately. No step is allowed to crash the loop.
    """

    def __init__(
        self,
        check: Callable[[], HealthResult],
        diagnose: Callable[[HealthResult], Path],
        agent: Optional[Callable[[Path], AgentOutcome]] = None,
        cooldown: float = 900.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.check = check
        self.diagnose = diagnose
        self.agent = agent
        self.cooldown = cooldown
        self.clock = clock
        self.sleep = sleep
        self._last_diagnosed: Optional[float] = None

    def run_once(self) -> CycleResult:
        try:
            health = self.check()
        except Exception as exc:  # noqa: BLE001
            log.exception("health check raised unexpectedly; treating as unhealthy")
            health = HealthResult([])
            health_error = f"health check error: {type(exc).__name__}: {exc}"
        else:
            health_error = None

        if health.healthy:
            if self._last_diagnosed is not None:
                log.info("network recovered")
            self._last_diagnosed = None
            log.info("network healthy\n%s", health.summary())
            return CycleResult(True, health)

        log.warning("network health check FAILED\n%s", health.summary() or health_error)
        now = self.clock()
        if self._last_diagnosed is not None and now - self._last_diagnosed < self.cooldown:
            log.info("outage continues; diagnostics already collected %.0fs ago", now - self._last_diagnosed)
            return CycleResult(False, health, error=health_error)
        self._last_diagnosed = now

        try:
            log_path = self.diagnose(health)
        except Exception as exc:  # noqa: BLE001
            log.exception("failed to collect diagnostics")
            return CycleResult(False, health, error=f"diagnostics failed: {type(exc).__name__}: {exc}")
        log.warning("diagnostics written to %s", log_path)

        outcome = None
        if self.agent is not None:
            try:
                outcome = self.agent(log_path)
            except Exception as exc:  # noqa: BLE001
                outcome = AgentOutcome(False, False, f"agent invocation error: {type(exc).__name__}: {exc}")
            level = logging.INFO if outcome.success else logging.WARNING
            log.log(level, "agent: %s%s", outcome.message,
                    f" (output: {outcome.output_path})" if outcome.output_path else "")
        return CycleResult(False, health, log_path, outcome, health_error)

    def run_forever(self, interval: float, max_cycles: Optional[int] = None) -> List[CycleResult]:
        results: List[CycleResult] = []
        while max_cycles is None or len(results) < max_cycles:
            started = self.clock()
            result = self.run_once()
            if max_cycles is not None:
                results.append(result)
                if len(results) >= max_cycles:
                    break
            self.sleep(max(0.0, interval - (self.clock() - started)))
        return results
