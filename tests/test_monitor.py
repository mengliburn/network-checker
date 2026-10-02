import logging
import tempfile
import unittest
from pathlib import Path

from network_checker.agent import AgentOutcome
from network_checker.health import HealthResult, ProbeResult, Target
from network_checker.monitor import Monitor

UP = HealthResult([ProbeResult(Target("1.1.1.1"), ok=True, latency_ms=5.0)])
DOWN = HealthResult([ProbeResult(Target("1.1.1.1"), ok=False, error="OSError: unreachable")])


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Harness:
    def __init__(self, results, cooldown=600.0, state_path=None):
        self.results = list(results)
        self.diagnosed = []
        self.agent_calls = []
        self.sleeps = []
        self.clock = Clock()
        self.diagnose_exc = None
        self.agent_exc = None
        self.check_exc = None
        self.monitor = Monitor(
            check=self.check,
            diagnose=self.diagnose,
            agent=self.agent,
            cooldown=cooldown,
            clock=self.clock,
            sleep=self.sleep,
            state_path=state_path,
        )

    def check(self):
        if self.check_exc:
            raise self.check_exc
        return self.results.pop(0)

    def diagnose(self, health):
        if self.diagnose_exc:
            raise self.diagnose_exc
        path = Path(f"/logs/diag-{len(self.diagnosed)}.log")
        self.diagnosed.append((health, path))
        return path

    def agent(self, path):
        self.agent_calls.append(path)
        if self.agent_exc:
            raise self.agent_exc
        return AgentOutcome(invoked=True, success=False, message="agent failed: network down")

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.clock.now += seconds


class QuietTestCase(unittest.TestCase):
    def setUp(self):
        logger = logging.getLogger("network_checker")
        handler = logging.NullHandler()
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)


class MonitorRunOnceTests(QuietTestCase):
    def test_healthy_check_does_not_run_diagnostics_or_agent(self):
        h = Harness([UP])
        cycle = h.monitor.run_once()
        self.assertTrue(cycle.healthy)
        self.assertEqual(h.diagnosed, [])
        self.assertEqual(h.agent_calls, [])

    def test_failed_check_runs_diagnostics_then_agent_with_log(self):
        h = Harness([DOWN])
        cycle = h.monitor.run_once()
        self.assertFalse(cycle.healthy)
        self.assertEqual(len(h.diagnosed), 1)
        self.assertIs(h.diagnosed[0][0], DOWN)
        self.assertEqual(h.agent_calls, [cycle.log_path])
        self.assertEqual(cycle.agent_outcome.message, "agent failed: network down")

    def test_repeated_failures_within_cooldown_do_not_spam_diagnostics(self):
        h = Harness([DOWN, DOWN, DOWN], cooldown=600)
        h.monitor.run_once()
        h.clock.now += 60
        second = h.monitor.run_once()
        self.assertIsNone(second.log_path)
        h.clock.now += 600
        third = h.monitor.run_once()
        self.assertIsNotNone(third.log_path)
        self.assertEqual(len(h.diagnosed), 2)

    def test_new_outage_after_recovery_is_diagnosed_immediately(self):
        h = Harness([DOWN, UP, DOWN], cooldown=600)
        h.monitor.run_once()
        h.clock.now += 10
        h.monitor.run_once()
        h.clock.now += 10
        cycle = h.monitor.run_once()
        self.assertIsNotNone(cycle.log_path)
        self.assertEqual(len(h.diagnosed), 2)

    def test_diagnostics_error_does_not_crash_and_skips_agent(self):
        h = Harness([DOWN])
        h.diagnose_exc = OSError("disk full")
        cycle = h.monitor.run_once()
        self.assertFalse(cycle.healthy)
        self.assertIsNone(cycle.log_path)
        self.assertIn("disk full", cycle.error)
        self.assertEqual(h.agent_calls, [])

    def test_agent_exception_does_not_crash(self):
        h = Harness([DOWN])
        h.agent_exc = RuntimeError("agent exploded")
        cycle = h.monitor.run_once()
        self.assertIsNotNone(cycle.log_path)
        self.assertFalse(cycle.agent_outcome.success)
        self.assertIn("agent exploded", cycle.agent_outcome.message)

    def test_unexpected_check_error_is_treated_as_unhealthy(self):
        h = Harness([])
        h.check_exc = RuntimeError("weird")
        cycle = h.monitor.run_once()
        self.assertFalse(cycle.healthy)
        self.assertEqual(len(h.diagnosed), 1)

    def test_no_agent_configured(self):
        h = Harness([DOWN])
        h.monitor.agent = None
        cycle = h.monitor.run_once()
        self.assertIsNotNone(cycle.log_path)
        self.assertIsNone(cycle.agent_outcome)


class MonitorPersistentCooldownTests(QuietTestCase):
    """--once runs are separate processes; cooldown must survive between them."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name) / "state.json"

    def test_cooldown_persists_across_monitor_instances(self):
        first = Harness([DOWN], cooldown=600, state_path=self.state)
        self.assertIsNotNone(first.monitor.run_once().log_path)
        second = Harness([DOWN], cooldown=600, state_path=self.state)
        second.clock.now = first.clock.now + 60
        self.assertIsNone(second.monitor.run_once().log_path)
        third = Harness([DOWN], cooldown=600, state_path=self.state)
        third.clock.now = first.clock.now + 601
        self.assertIsNotNone(third.monitor.run_once().log_path)

    def test_recovery_clears_persisted_cooldown(self):
        Harness([DOWN], state_path=self.state).monitor.run_once()
        Harness([UP], state_path=self.state).monitor.run_once()
        later = Harness([DOWN], state_path=self.state)
        self.assertIsNotNone(later.monitor.run_once().log_path)

    def test_corrupt_or_unwritable_state_is_ignored(self):
        self.state.write_text("{not json")
        self.assertIsNotNone(Harness([DOWN], state_path=self.state).monitor.run_once().log_path)
        unwritable = self.state / "nested" / "state.json"  # parent is a file
        self.assertIsNotNone(Harness([DOWN], state_path=unwritable).monitor.run_once().log_path)


class MonitorRunForeverTests(QuietTestCase):
    def test_runs_requested_cycles_sleeping_between_them(self):
        h = Harness([UP, DOWN, UP])
        cycles = h.monitor.run_forever(interval=30, max_cycles=3)
        self.assertEqual([c.healthy for c in cycles], [True, False, True])
        self.assertEqual(h.sleeps, [30, 30])

    def test_interval_accounts_for_time_spent_in_cycle(self):
        h = Harness([DOWN, UP])

        def slow_diagnose(health):
            h.clock.now += 20
            return Path("/logs/x.log")

        h.monitor.diagnose = slow_diagnose
        h.monitor.run_forever(interval=30, max_cycles=2)
        self.assertEqual(h.sleeps, [10])


if __name__ == "__main__":
    unittest.main()
