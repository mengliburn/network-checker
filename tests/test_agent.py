import tempfile
import unittest
from pathlib import Path

from network_checker.agent import (
    DEFAULT_AGENT_COMMAND,
    MAX_LOG_BYTES_IN_PROMPT,
    build_prompt,
    invoke_agent,
)
from network_checker.diagnostics import CommandResult, run_command


class FakeRunner:
    def __init__(self, result=None, exc=None):
        self.result = result or CommandResult(returncode=0, output="Root cause: DNS server unreachable")
        self.exc = exc
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        if self.exc:
            raise self.exc
        return self.result


class InvokeAgentTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.log = Path(self._tmp.name) / "diagnostics-20260102T030405Z.log"
        self.log.write_text("===== dns resolution =====\nwww.google.com: FAILED\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_successful_invocation_saves_agent_output_next_to_log(self):
        runner = FakeRunner()
        outcome = invoke_agent(self.log, ["agent", "--log", "{log_file}"], runner=runner)
        self.assertTrue(outcome.invoked)
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.output_path, self.log.with_suffix(".agent.log"))
        self.assertIn("Root cause: DNS server unreachable", outcome.output_path.read_text())

    def test_placeholders_are_substituted_per_argument_without_shell(self):
        runner = FakeRunner()
        invoke_agent(self.log, ["agent", "-p", "{prompt}", "--file={log_file}"], runner=runner, timeout=42)
        argv, timeout = runner.calls[0]
        self.assertEqual(timeout, 42)
        self.assertEqual(argv[0], "agent")
        self.assertIn(str(self.log), argv[2])
        self.assertEqual(argv[3], f"--file={self.log}")
        self.assertEqual(len(argv), 4)

    def test_braces_in_log_content_do_not_break_substitution(self):
        self.log.write_text("weird {log_file} {0} {prompt} content")
        runner = FakeRunner()
        outcome = invoke_agent(self.log, ["agent", "{prompt}"], runner=runner)
        self.assertTrue(outcome.success)
        self.assertIn("weird {log_file} {0} {prompt} content", runner.calls[0][0][1])

    def test_missing_agent_executable_is_reported_not_raised(self):
        outcome = invoke_agent(self.log, ["agent"], runner=FakeRunner(exc=FileNotFoundError("agent")))
        self.assertFalse(outcome.invoked)
        self.assertFalse(outcome.success)
        self.assertIn("not found", outcome.message)
        self.assertIn("not found", outcome.output_path.read_text())

    def test_agent_failing_due_to_network_is_reported_not_raised(self):
        result = CommandResult(returncode=1, output="Error: getaddrinfo ENOTFOUND api.example.com")
        outcome = invoke_agent(self.log, ["agent"], runner=FakeRunner(result=result))
        self.assertTrue(outcome.invoked)
        self.assertFalse(outcome.success)
        self.assertIn("exit code 1", outcome.message)
        self.assertIn("ENOTFOUND", outcome.output_path.read_text())

    def test_agent_timeout_is_reported(self):
        result = CommandResult(returncode=None, output="partial", timed_out=True)
        outcome = invoke_agent(self.log, ["agent"], runner=FakeRunner(result=result), timeout=5)
        self.assertFalse(outcome.success)
        self.assertIn("timed out", outcome.message)

    def test_unexpected_exception_is_reported_not_raised(self):
        outcome = invoke_agent(self.log, ["agent"], runner=FakeRunner(exc=RuntimeError("kaboom")))
        self.assertFalse(outcome.success)
        self.assertIn("kaboom", outcome.message)

    def test_empty_command_disables_agent(self):
        runner = FakeRunner()
        outcome = invoke_agent(self.log, [], runner=runner)
        self.assertFalse(outcome.invoked)
        self.assertEqual(runner.calls, [])
        self.assertIsNone(outcome.output_path)

    def test_unreadable_log_still_invokes_agent(self):
        missing = Path(self._tmp.name) / "diagnostics-missing.log"
        runner = FakeRunner()
        outcome = invoke_agent(missing, ["agent", "{prompt}"], runner=runner)
        self.assertTrue(outcome.invoked)
        self.assertIn(str(missing), runner.calls[0][0][1])

    def test_huge_non_ascii_log_can_still_be_passed_to_a_real_process(self):
        self.log.write_text("\u00e9\ufffd" * 200_000, encoding="utf-8")
        outcome = invoke_agent(
            self.log, ["python3", "-c", "import sys; print(len(sys.argv[1]))", "{prompt}"], runner=run_command
        )
        self.assertTrue(outcome.invoked, outcome.message)
        self.assertTrue(outcome.success, outcome.message)

    def test_default_command_passes_prompt(self):
        self.assertIn("{prompt}", DEFAULT_AGENT_COMMAND)


class BuildPromptTests(unittest.TestCase):
    def test_prompt_contains_path_and_log_content(self):
        prompt = build_prompt(Path("/x/diag.log"), "LOG BODY")
        self.assertIn("/x/diag.log", prompt)
        self.assertIn("LOG BODY", prompt)

    def test_long_logs_are_truncated_keeping_head_and_tail(self):
        body = "HEAD" + "A" * (MAX_LOG_BYTES_IN_PROMPT * 2) + "TAIL"
        prompt = build_prompt(Path("/x/diag.log"), body)
        self.assertLess(len(prompt), MAX_LOG_BYTES_IN_PROMPT + 2000)
        self.assertIn("truncated", prompt)
        self.assertIn("HEAD", prompt)
        self.assertIn("TAIL", prompt)

    def test_truncation_is_by_encoded_bytes_for_non_ascii_logs(self):
        body = "\ufffd" * (MAX_LOG_BYTES_IN_PROMPT * 2)
        prompt = build_prompt(Path("/x/diag.log"), body)
        self.assertLess(len(prompt.encode("utf-8")), MAX_LOG_BYTES_IN_PROMPT + 2000)

    def test_prompt_fits_windows_command_line_limit(self):
        prompt = build_prompt(Path("/x/diag.log"), "x" * 1_000_000)
        self.assertLess(len(prompt), 30_000)


if __name__ == "__main__":
    unittest.main()
