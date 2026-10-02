import subprocess
import sys

import pytest

from network_checker import cli
from network_checker.health import HealthResult, Target, TargetResult


def test_parse_target_ipv4_hostname_and_ipv6():
    assert cli.parse_target("example.com:443") == Target("example.com", 443)
    assert cli.parse_target("1.1.1.1") == Target("1.1.1.1", 443)
    assert cli.parse_target("[2606:4700:4700::1111]:443") == Target("2606:4700:4700::1111", 443)


@pytest.mark.parametrize("bad", ["host:notaport", "host:70000", ""])
def test_parse_target_rejects_bad_values(bad):
    with pytest.raises(Exception):
        cli.parse_target(bad)


def _patch(monkeypatch, healthy, tmp_path):
    result = HealthResult([TargetResult(Target("x", 1), healthy, 1.0, None if healthy else "boom")])
    monkeypatch.setattr(cli, "check_health", lambda targets, timeout: result)
    calls = {}

    def fake_diag(health, log_dir, **kw):
        calls["diag"] = log_dir
        p = tmp_path / "d.log"
        p.write_text("x", encoding="utf-8")
        return p

    monkeypatch.setattr(cli, "run_diagnostics", fake_diag)

    def fake_agent(log_path, argv, timeout):
        calls["agent"] = argv
        from network_checker.agent import AgentOutcome
        return AgentOutcome(True, True, "ok", None)

    monkeypatch.setattr(cli, "invoke_agent", fake_agent)
    return calls


def test_once_exit_code_zero_when_healthy(monkeypatch, tmp_path):
    calls = _patch(monkeypatch, True, tmp_path)
    assert cli.main(["--once", "--log-dir", str(tmp_path)]) == 0
    assert "diag" not in calls


def test_once_exit_code_one_and_diagnoses_when_unhealthy(monkeypatch, tmp_path):
    calls = _patch(monkeypatch, False, tmp_path)
    rc = cli.main(["--once", "--log-dir", str(tmp_path), "--agent-cmd", "my-agent {log}"])
    assert rc == 1
    assert str(calls["diag"]) == str(tmp_path)
    assert calls["agent"][0] == "my-agent"


def test_agent_cmd_can_come_from_environment(monkeypatch, tmp_path):
    calls = _patch(monkeypatch, False, tmp_path)
    monkeypatch.setenv("NETWORK_CHECKER_AGENT_CMD", "env-agent {log}")
    cli.main(["--once", "--log-dir", str(tmp_path)])
    assert calls["agent"][0] == "env-agent"


def test_ctrl_c_exits_cleanly(monkeypatch, tmp_path):
    _patch(monkeypatch, True, tmp_path)

    def interrupt(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.Monitor, "run_forever", interrupt)
    assert cli.main(["--log-dir", str(tmp_path)]) == 0


def test_module_is_runnable_with_python_dash_m():
    out = subprocess.run([sys.executable, "-m", "network_checker", "--help"],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0
    assert "--once" in out.stdout


def test_malformed_agent_command_is_a_usage_error_not_a_crash(monkeypatch, tmp_path, capsys):
    _patch(monkeypatch, True, tmp_path)
    with pytest.raises(SystemExit) as info:
        cli.main(["--once", "--log-dir", str(tmp_path), "--agent-cmd", "agent 'x"])
    assert info.value.code == 2
    assert "agent" in capsys.readouterr().err.lower()


def test_custom_targets_are_added_to_verified_defaults(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(cli, "check_health", lambda targets, timeout: seen.setdefault("t", list(targets)) and
                        HealthResult([TargetResult(Target("x", 1), True, 1.0)]))
    cli.main(["--once", "--log-dir", str(tmp_path), "--target", "intranet.example:443"])
    assert Target("intranet.example", 443) in seen["t"]
    assert any(t.path for t in seen["t"])  # content-verified probes still present


def test_no_default_targets_flag_replaces_defaults(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(cli, "check_health", lambda targets, timeout: seen.setdefault("t", list(targets)) and
                        HealthResult([TargetResult(Target("x", 1), True, 1.0)]))
    cli.main(["--once", "--log-dir", str(tmp_path), "--no-default-targets", "--target", "a.example:1"])
    assert seen["t"] == [Target("a.example", 1)]


def test_no_default_targets_requires_a_target(tmp_path):
    with pytest.raises(SystemExit) as info:
        cli.main(["--once", "--log-dir", str(tmp_path), "--no-default-targets"])
    assert info.value.code == 2
