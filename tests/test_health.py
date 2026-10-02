import socket
import unittest

from network_checker.health import (
    DEFAULT_TARGETS,
    HealthResult,
    Target,
    check_health,
    probe_target,
)


class FakeConnector:
    """Records calls and fails for the hosts listed in ``failing``."""

    def __init__(self, failing=(), exc=OSError("unreachable")):
        self.failing = set(failing)
        self.exc = exc
        self.calls = []

    def __call__(self, address, timeout):
        self.calls.append((address, timeout))
        if address[0] in self.failing:
            raise self.exc
        return FakeSocket()


class FakeSocket:
    closed = False

    def close(self):
        self.closed = True


class ProbeTargetTests(unittest.TestCase):
    def test_success_reports_ok_and_latency(self):
        connector = FakeConnector()
        result = probe_target(Target("1.1.1.1", 443), timeout=2.0, connector=connector)
        self.assertTrue(result.ok)
        self.assertIsNone(result.error)
        self.assertGreaterEqual(result.latency_ms, 0)
        self.assertEqual(connector.calls, [(("1.1.1.1", 443), 2.0)])

    def test_failure_reports_error_instead_of_raising(self):
        connector = FakeConnector(failing={"1.1.1.1"})
        result = probe_target(Target("1.1.1.1", 443), timeout=2.0, connector=connector)
        self.assertFalse(result.ok)
        self.assertIn("unreachable", result.error)
        self.assertIsNone(result.latency_ms)

    def test_timeout_is_a_failure(self):
        connector = FakeConnector(failing={"8.8.8.8"}, exc=socket.timeout("timed out"))
        result = probe_target(Target("8.8.8.8", 53), timeout=1.0, connector=connector)
        self.assertFalse(result.ok)
        self.assertIn("timed out", result.error)

    def test_dns_failure_is_a_failure(self):
        connector = FakeConnector(failing={"www.google.com"}, exc=socket.gaierror("name resolution"))
        result = probe_target(Target("www.google.com", 443), timeout=1.0, connector=connector)
        self.assertFalse(result.ok)


class CheckHealthTests(unittest.TestCase):
    targets = [Target("1.1.1.1", 443), Target("8.8.8.8", 53), Target("www.google.com", 443)]

    def test_healthy_when_all_targets_reachable(self):
        result = check_health(self.targets, connector=FakeConnector())
        self.assertIsInstance(result, HealthResult)
        self.assertTrue(result.healthy)
        self.assertEqual(len(result.probes), 3)

    def test_healthy_when_at_least_one_target_reachable(self):
        # A single flaky provider must not trigger a false alarm.
        result = check_health(self.targets, connector=FakeConnector(failing={"1.1.1.1", "8.8.8.8"}))
        self.assertTrue(result.healthy)

    def test_unhealthy_when_all_targets_fail(self):
        failing = {t.host for t in self.targets}
        result = check_health(self.targets, connector=FakeConnector(failing=failing))
        self.assertFalse(result.healthy)
        self.assertTrue(all(not p.ok for p in result.probes))

    def test_unhealthy_when_no_targets(self):
        self.assertFalse(check_health([], connector=FakeConnector()).healthy)

    def test_summary_mentions_each_target(self):
        result = check_health(self.targets, connector=FakeConnector(failing={"8.8.8.8"}))
        summary = result.summary()
        for t in self.targets:
            self.assertIn(t.host, summary)
        self.assertIn("FAIL", summary)
        self.assertIn("OK", summary)

    def test_default_targets_cover_multiple_independent_providers(self):
        hosts = {t.host for t in DEFAULT_TARGETS}
        self.assertGreaterEqual(len(hosts), 3)
        self.assertIn("1.1.1.1", hosts)
        self.assertIn("8.8.8.8", hosts)


class TargetParseTests(unittest.TestCase):
    def test_parse_host_and_port(self):
        self.assertEqual(Target.parse("example.com:80"), Target("example.com", 80))

    def test_parse_defaults_to_443(self):
        self.assertEqual(Target.parse("example.com"), Target("example.com", 443))

    def test_parse_rejects_bad_port(self):
        with self.assertRaises(ValueError):
            Target.parse("example.com:notaport")
        with self.assertRaises(ValueError):
            Target.parse("example.com:70000")


if __name__ == "__main__":
    unittest.main()
