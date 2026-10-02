import sys
from pathlib import Path

import pytest

from network_checker.agent import build_prompt, invoke_agent, parse_agent_command
from network_checker.diagnostics import CommandOutput


@pytest.fixture
def log_path(tmp_path):
    p = tmp_path / "diag-20261002T170405Z.log"
    p.write_text("diag", encoding="utf-8")
    p.with_suffix(".json").write_text("{}", encoding="utf-8")
    return p


def test_prompt_points_agent_at_both_logs(log_path):
    prompt = build_prompt(log_path)
    assert str(log_path) in prompt
    assert str(log_path.with_suffix(".json")) in prompt
    assert "diagnose" in prompt.lower()


def test_no_agent_configured_is_skipped_not_failed(log_path):
    outcome = invoke_agent(log_path, None)
    assert outcome.attempted is False
    assert outcome.success is False
    assert "no agent" in outcome.detail.lower()


def test_placeholders_are_substituted_into_argv(log_path):
    seen = []

    def runner(argv, timeout):
        seen.append((argv, timeout))
        return CommandOutput(0, "root cause: wifi down", "", None)

    outcome = invoke_agent(log_path, ["my-agent", "--log", "{log}", "-p", "{prompt}"], runner=runner, timeout=42)
    argv, timeout = seen[0]
    assert argv[:3] == ["my-agent", "--log", str(log_path)]
    assert argv[4] == build_prompt(log_path)
    assert timeout == 42
    assert outcome.attempted and outcome.success


def test_agent_output_is_saved_next_to_logs(log_path):
    runner = lambda argv, timeout: CommandOutput(0, "root cause: wifi down", "warn", None)
    outcome = invoke_agent(log_path, ["agent"], runner=runner)
    saved = Path(outcome.output_path).read_text(encoding="utf-8")
    assert outcome.output_path.parent == log_path.parent
    assert "root cause: wifi down" in saved and "warn" in saved


@pytest.mark.parametrize("result", [
    CommandOutput(None, "", "", "command not found: agent"),
    CommandOutput(None, "", "", "timed out after 600s"),
    CommandOutput(7, "", "network unreachable", None),
])
def test_agent_failures_are_tolerated_and_recorded(log_path, result):
    outcome = invoke_agent(log_path, ["agent"], runner=lambda a, t: result)
    assert outcome.attempted is True
    assert outcome.success is False
    assert outcome.detail
    text = Path(outcome.output_path).read_text(encoding="utf-8")
    assert "FAILED" in text  # a later agent can see the attempt failed


def test_runner_exception_never_propagates(log_path):
    def boom(argv, timeout):
        raise RuntimeError("kaboom")

    outcome = invoke_agent(log_path, ["agent"], runner=boom)
    assert outcome.success is False and "kaboom" in outcome.detail


def test_invoke_agent_with_real_process(log_path):
    code = "import sys; print('analysed', sys.argv[1])"
    outcome = invoke_agent(log_path, [sys.executable, "-c", code, "{log}"], timeout=30)
    assert outcome.success, outcome.detail
    assert str(log_path) in Path(outcome.output_path).read_text(encoding="utf-8")


def test_parse_agent_command_posix_style():
    assert parse_agent_command("copilot -p '{prompt}' --allow-all-tools", windows=False) == [
        "copilot", "-p", "{prompt}", "--allow-all-tools"]


def test_parse_agent_command_keeps_windows_backslashes():
    argv = parse_agent_command(r'"C:\Program Files\agent\agent.exe" --log {log}', windows=True)
    assert argv == [r"C:\Program Files\agent\agent.exe", "--log", "{log}"]


def test_parse_agent_command_empty_means_none():
    assert parse_agent_command("", windows=False) is None
    assert parse_agent_command(None, windows=False) is None
