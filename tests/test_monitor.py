from pathlib import Path

import pytest

from network_checker.agent import AgentOutcome
from network_checker.health import HealthResult, Target, TargetResult
from network_checker.monitor import Monitor


def healthy():
    return HealthResult([TargetResult(Target("1.1.1.1", 443), True, 10.0)])


def unhealthy():
    return HealthResult([TargetResult(Target("1.1.1.1", 443), False, 5000.0, "TimeoutError")])


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class Recorder:
    def __init__(self, tmp_path, fail_diag=False, fail_agent=False):
        self.tmp_path = tmp_path
        self.diag_calls = []
        self.agent_calls = []
        self.fail_diag = fail_diag
        self.fail_agent = fail_agent

    def diagnose(self, health):
        self.diag_calls.append(health)
        if self.fail_diag:
            raise OSError("disk full")
        p = self.tmp_path / f"diag-{len(self.diag_calls)}.log"
        p.write_text("x", encoding="utf-8")
        return p

    def agent(self, log_path):
        self.agent_calls.append(log_path)
        if self.fail_agent:
            raise RuntimeError("agent exploded")
        return AgentOutcome(True, False, "network unreachable", None)


def make(tmp_path, results, **kw):
    rec = Recorder(tmp_path, kw.pop("fail_diag", False), kw.pop("fail_agent", False))
    it = iter(results)
    clock = Clock()
    mon = Monitor(check=lambda: next(it), diagnose=rec.diagnose, agent=rec.agent,
                  log_dir=tmp_path, clock=clock, **kw)
    return mon, rec, clock


def test_healthy_check_runs_no_diagnostics(tmp_path):
    mon, rec, _ = make(tmp_path, [healthy()])
    assert mon.run_once().healthy is True
    assert rec.diag_calls == [] and rec.agent_calls == []


def test_failure_triggers_diagnostics_then_agent(tmp_path):
    mon, rec, _ = make(tmp_path, [unhealthy()])
    mon.run_once()
    assert len(rec.diag_calls) == 1
    assert rec.agent_calls == [tmp_path / "diag-1.log"]


def test_persistent_outage_is_not_rediagnosed_until_cooldown(tmp_path):
    mon, rec, clock = make(tmp_path, [unhealthy()] * 3, cooldown=300)
    mon.run_once()
    clock.t = 60
    mon.run_once()
    assert len(rec.diag_calls) == 1
    clock.t = 301
    mon.run_once()
    assert len(rec.diag_calls) == 2


def test_new_outage_after_recovery_is_diagnosed_immediately(tmp_path):
    mon, rec, clock = make(tmp_path, [unhealthy(), healthy(), unhealthy()], cooldown=300)
    mon.run_once()
    clock.t = 10
    mon.run_once()
    clock.t = 20
    mon.run_once()
    assert len(rec.diag_calls) == 2


def test_diagnostics_failure_does_not_crash_and_still_tries_agent_without_log(tmp_path):
    mon, rec, _ = make(tmp_path, [unhealthy()], fail_diag=True)
    mon.run_once()  # must not raise
    assert rec.agent_calls == []  # nothing to analyse
    assert "disk full" in (tmp_path / "health.log").read_text(encoding="utf-8")


def test_agent_exception_does_not_crash_monitor(tmp_path):
    mon, rec, _ = make(tmp_path, [unhealthy(), healthy()], fail_agent=True)
    mon.run_once()
    assert mon.run_once().healthy is True
    assert "agent exploded" in (tmp_path / "health.log").read_text(encoding="utf-8")


def test_agent_can_be_disabled(tmp_path):
    rec = Recorder(tmp_path)
    mon = Monitor(check=unhealthy, diagnose=rec.diagnose, agent=None, log_dir=tmp_path)
    mon.run_once()
    assert len(rec.diag_calls) == 1


def test_every_check_is_appended_to_history_log(tmp_path):
    mon, _, _ = make(tmp_path, [healthy(), unhealthy(), healthy()])
    for _ in range(3):
        mon.run_once()
    lines = (tmp_path / "health.log").read_text(encoding="utf-8").splitlines()
    status_lines = [l for l in lines if " HEALTHY " in l or " UNHEALTHY " in l]
    assert len(status_lines) == 3
    assert any("RECOVERED" in l for l in lines)


def test_run_forever_sleeps_between_checks_and_honours_max_iterations(tmp_path):
    sleeps = []
    mon, _, _ = make(tmp_path, [healthy()] * 3)
    mon.sleep = sleeps.append
    mon.run_forever(interval=30, max_iterations=3)
    assert sleeps == [30, 30]


def test_check_exception_is_treated_as_unhealthy(tmp_path):
    rec = Recorder(tmp_path)

    def broken():
        raise RuntimeError("bug in check")

    mon = Monitor(check=broken, diagnose=rec.diagnose, agent=None, log_dir=tmp_path)
    assert mon.run_once().healthy is False
    assert len(rec.diag_calls) == 1
