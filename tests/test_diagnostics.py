import datetime as dt
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from network_checker.diagnostics import (
    CommandResult,
    DiagnosticCommand,
    default_commands,
    run_command,
    run_diagnostics,
)
from network_checker.health import HealthResult, ProbeResult, Target

FIXED_NOW = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)


def failed_health():
    return HealthResult([ProbeResult(Target("1.1.1.1", 443), ok=False, error="OSError: unreachable")])


class FakeRunner:
    def __init__(self, behaviours=None):
        self.behaviours = behaviours or {}
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        behaviour = self.behaviours.get(argv[0])
        if isinstance(behaviour, BaseException):
            raise behaviour
        if behaviour is not None:
            return behaviour
        return CommandResult(returncode=0, output=f"output of {' '.join(argv)}")


def ok_resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.0.1", 443))]


def failing_resolver(host, port):
    raise socket.gaierror(-2, "Name or service not known")


class RunDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.log_dir = Path(self._tmp.name) / "logs"

    def tearDown(self):
        self._tmp.cleanup()

    def run_diag(self, **kwargs):
        kwargs.setdefault("runner", FakeRunner())
        kwargs.setdefault("resolver", ok_resolver)
        kwargs.setdefault("now", lambda: FIXED_NOW)
        kwargs.setdefault(
            "commands",
            [DiagnosticCommand("routes", ["ip", "route"]), DiagnosticCommand("ping", ["ping", "-c", "1", "8.8.8.8"])],
        )
        return run_diagnostics(failed_health(), self.log_dir, **kwargs)

    def test_creates_timestamped_log_file_in_new_directory(self):
        path = self.run_diag()
        self.assertTrue(path.exists())
        self.assertEqual(path.parent, self.log_dir)
        self.assertEqual(path.name, "diagnostics-20260102T030405Z.log")

    def test_log_contains_health_summary_and_command_outputs(self):
        content = self.run_diag().read_text()
        self.assertIn("2026-01-02T03:04:05", content)
        self.assertIn("FAIL 1.1.1.1:443", content)
        self.assertIn("routes", content)
        self.assertIn("output of ip route", content)
        self.assertIn("output of ping -c 1 8.8.8.8", content)

    def test_runs_every_command_with_timeout(self):
        runner = FakeRunner()
        self.run_diag(runner=runner, command_timeout=7)
        self.assertEqual([c[0][0] for c in runner.calls], ["ip", "ping"])
        self.assertTrue(all(c[1] == 7 for c in runner.calls))

    def test_missing_or_failing_commands_are_logged_not_raised(self):
        runner = FakeRunner(
            {
                "ip": FileNotFoundError("no such file: ip"),
                "ping": CommandResult(returncode=1, output="", timed_out=True),
            }
        )
        content = self.run_diag(runner=runner).read_text()
        self.assertIn("not available", content)
        self.assertIn("timed out", content.lower())

    def test_unexpected_runner_exception_is_logged_and_remaining_commands_run(self):
        runner = FakeRunner({"ip": RuntimeError("boom")})
        content = self.run_diag(runner=runner).read_text()
        self.assertIn("boom", content)
        self.assertIn("output of ping -c 1 8.8.8.8", content)

    def test_dns_resolution_results_are_logged(self):
        content = self.run_diag(resolver=ok_resolver, dns_hosts=["www.google.com"]).read_text()
        self.assertIn("www.google.com", content)
        self.assertIn("142.250.0.1", content)

    def test_dns_failure_is_logged(self):
        content = self.run_diag(resolver=failing_resolver, dns_hosts=["www.google.com"]).read_text()
        self.assertIn("Name or service not known", content)

    def test_hanging_dns_lookup_is_bounded_by_timeout(self):
        def hanging_resolver(host, port):
            time.sleep(2)
            return []

        start = time.monotonic()
        content = self.run_diag(resolver=hanging_resolver, dns_hosts=["a.example", "b.example"], dns_timeout=0.1).read_text()
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertIn("a.example: FAILED (timed out", content)
        self.assertIn("b.example: FAILED (timed out", content)

    def test_unwritable_log_dir_raises_oserror(self):
        # Documented contract: callers (the monitor) handle OSError.
        blocker = Path(self._tmp.name) / "file"
        blocker.write_text("not a dir")
        with self.assertRaises(OSError):
            run_diagnostics(failed_health(), blocker / "logs", commands=[], dns_hosts=[])

    def test_does_not_overwrite_existing_log_with_same_timestamp(self):
        first = self.run_diag()
        second = self.run_diag()
        self.assertNotEqual(first, second)
        self.assertTrue(first.exists() and second.exists())


class RunCommandTests(unittest.TestCase):
    def test_captures_output_and_return_code(self):
        result = run_command(["python3", "-c", "import sys; print('hi'); sys.exit(3)"], timeout=10)
        self.assertEqual(result.returncode, 3)
        self.assertIn("hi", result.output)
        self.assertFalse(result.timed_out)

    def test_timeout_is_reported(self):
        result = run_command(["python3", "-c", "import time; time.sleep(5)"], timeout=0.2)
        self.assertTrue(result.timed_out)

    def test_missing_executable_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            run_command(["definitely-not-a-real-binary-xyz"], timeout=1)


class DefaultCommandsTests(unittest.TestCase):
    def test_linux_commands_cover_interfaces_routes_dns_and_reachability(self):
        names = " ".join(c.name for c in default_commands("linux"))
        for keyword in ("interfaces", "routes", "dns", "ping", "traceroute"):
            self.assertIn(keyword, names)

    def test_other_platforms_have_commands(self):
        self.assertTrue(default_commands("darwin"))
        self.assertTrue(default_commands("win32"))

    def test_commands_never_use_a_shell_string(self):
        for platform in ("linux", "darwin", "win32"):
            for cmd in default_commands(platform):
                self.assertIsInstance(cmd.argv, list)


if __name__ == "__main__":
    unittest.main()
