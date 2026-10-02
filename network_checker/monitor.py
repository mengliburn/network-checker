"""Periodic health monitoring that diagnoses outages and calls an agent."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Union

from .agent import AgentOutcome
from .health import HealthResult, Target, TargetResult

HISTORY_FILE = "health.log"


class Monitor:
    def __init__(
        self,
        check: Callable[[], HealthResult],
        diagnose: Callable[[HealthResult], Path],
        agent: Optional[Callable[[Path], AgentOutcome]],
        log_dir: Union[str, Path],
        cooldown: float = 900.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        echo: Callable[[str], None] = lambda line: None,
    ):
        self.check = check
        self.diagnose = diagnose
        self.agent = agent
        self.log_dir = Path(log_dir)
        self.cooldown = cooldown
        self.clock = clock
        self.sleep = sleep
        self.echo = echo
        self._was_healthy: Optional[bool] = None
        self._last_diagnosis: Optional[float] = None

    def _log(self, message: str) -> None:
        line = f"{datetime.now(timezone.utc).isoformat()} {message}"
        self.echo(line)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            with open(self.log_dir / HISTORY_FILE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass  # logging must never take the monitor down

    def run_once(self) -> HealthResult:
        try:
            result = self.check()
        except Exception as exc:
            result = HealthResult([TargetResult(Target("health-check", 0), False, 0.0,
                                                f"{type(exc).__name__}: {exc}")])

        status = "HEALTHY" if result.healthy else "UNHEALTHY"
        self._log(f"{status} {result.summary()}")

        if result.healthy:
            if self._was_healthy is False:
                self._log("RECOVERED network is healthy again")
            self._last_diagnosis = None
        elif self._should_diagnose():
            self._handle_outage(result)
        self._was_healthy = result.healthy
        return result

    def _should_diagnose(self) -> bool:
        if self._last_diagnosis is None:
            return True
        return self.clock() - self._last_diagnosis >= self.cooldown

    def _handle_outage(self, result: HealthResult) -> None:
        self._last_diagnosis = self.clock()
        try:
            log_path = self.diagnose(result)
        except Exception as exc:
            self._log(f"DIAGNOSTICS_FAILED {type(exc).__name__}: {exc}")
            return
        self._log(f"DIAGNOSTICS_WRITTEN {log_path}")
        if self.agent is None:
            return
        try:
            outcome = self.agent(log_path)
        except Exception as exc:
            self._log(f"AGENT_FAILED {type(exc).__name__}: {exc}")
            return
        state = "AGENT_OK" if outcome.success else ("AGENT_FAILED" if outcome.attempted else "AGENT_SKIPPED")
        where = f" output={outcome.output_path}" if outcome.output_path else ""
        self._log(f"{state} {outcome.detail}{where}")

    def run_forever(self, interval: float, max_iterations: Optional[int] = None) -> None:
        n = 0
        while True:
            self.run_once()
            n += 1
            if max_iterations is not None and n >= max_iterations:
                return
            self.sleep(interval)
