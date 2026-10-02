import logging
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from network_checker import cli
from network_checker.agent import DEFAULT_AGENT_COMMAND
from network_checker.diagnostics import DiagnosticCommand
from network_checker.health import DEFAULT_TARGETS, Target

QUICK_COMMANDS = [DiagnosticCommand("python", ["python3", "-c", "print('diag ok')"])]


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ParseArgsTests(unittest.TestCase):
    def test_defaults(self):
        args = cli.parse_args([])
        self.assertEqual(args.targets, list(DEFAULT_TARGETS))
        self.assertEqual(args.agent_cmd, list(DEFAULT_AGENT_COMMAND))
        self.assertFalse(args.once)
        self.assertGreater(args.interval, 0)

    def test_custom_targets_and_agent_command(self):
        args = cli.parse_args(["-t", "example.com:80", "-t", "[::1]:53", "--agent-cmd", "my-agent --file '{log_file}'"])
        self.assertEqual(args.targets, [Target("example.com", 80), Target("::1", 53)])
        self.assertEqual(args.agent_cmd, ["my-agent", "--file", "{log_file}"])

    def test_no_agent(self):
        self.assertEqual(cli.parse_args(["--no-agent"]).agent_cmd, [])

    def test_invalid_target_is_a_usage_error(self):
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            cli.parse_args(["-t", "host:99999"])

    def test_non_positive_interval_is_a_usage_error(self):
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            cli.parse_args(["--interval", "0"])


class MainOnceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.log_dir = Path(self._tmp.name)

    def tearDown(self):
        logger = logging.getLogger("network_checker")
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
        self._tmp.cleanup()

    def test_once_healthy_exits_zero_and_writes_no_diagnostics(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        self.addCleanup(server.close)
        port = server.getsockname()[1]
        code = cli.main(["--once", "-q", "-t", f"127.0.0.1:{port}", "--log-dir", str(self.log_dir), "--no-agent"])
        self.assertEqual(code, 0)
        self.assertEqual(list(self.log_dir.glob("diagnostics-*.log")), [])

    def test_once_unhealthy_exits_one_writes_diagnostics_and_tries_agent(self):
        agent = "python3 -c \"import sys; print('AGENT SAW', sys.argv[1]); sys.exit(2)\" {log_file}"
        with mock.patch.object(cli, "default_commands", return_value=QUICK_COMMANDS):
            code = cli.main(
                ["--once", "-t", f"127.0.0.1:{closed_port()}", "--log-dir", str(self.log_dir), "--agent-cmd", agent]
            )
        self.assertEqual(code, 1)
        logs = list(self.log_dir.glob("diagnostics-*Z.log"))
        self.assertEqual(len(logs), 1)
        self.assertIn("diag ok", logs[0].read_text())
        agent_log = logs[0].with_suffix(".agent.log").read_text()
        self.assertIn("AGENT SAW " + str(logs[0]), agent_log)
        self.assertIn("exit code 2", agent_log)
        self.assertTrue((self.log_dir / "network-checker.log").exists())

    def test_repeated_once_runs_respect_cooldown(self):
        argv = ["--once", "-q", "-t", f"127.0.0.1:{closed_port()}", "--log-dir", str(self.log_dir), "--no-agent"]
        with mock.patch.object(cli, "default_commands", return_value=QUICK_COMMANDS):
            self.assertEqual(cli.main(argv), 1)
            self.assertEqual(cli.main(argv), 1)
        self.assertEqual(len(list(self.log_dir.glob("diagnostics-*.log"))), 1)

    def test_once_unhealthy_with_missing_agent_still_completes(self):
        with mock.patch.object(cli, "default_commands", return_value=QUICK_COMMANDS):
            code = cli.main(
                [
                    "--once",
                    "-t",
                    f"127.0.0.1:{closed_port()}",
                    "--log-dir",
                    str(self.log_dir),
                    "--agent-cmd",
                    "definitely-not-a-real-agent-xyz",
                ]
            )
        self.assertEqual(code, 1)
        agent_logs = list(self.log_dir.glob("*.agent.log"))
        self.assertEqual(len(agent_logs), 1)
        self.assertIn("not found", agent_logs[0].read_text())


if __name__ == "__main__":
    unittest.main()
