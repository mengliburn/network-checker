import json
import subprocess
import sys
from datetime import datetime, timezone

import pytest

from network_checker import diagnostics as diag_mod
from network_checker.diagnostics import (
    CommandOutput,
    commands_for_platform,
    run_command,
    run_diagnostics,
)
from network_checker.health import HealthResult, Target, TargetResult

FIXED_NOW = datetime(2026, 10, 2, 17, 4, 5, tzinfo=timezone.utc)


def failing_health():
    return HealthResult([TargetResult(Target("1.1.1.1", 443), False, 5000.0, "TimeoutError: timed out")])


def names_and_programs(system):
    cmds = commands_for_platform(system)
    return {name for name, _ in cmds}, {argv[0] for _, argv in cmds}


@pytest.mark.parametrize("system", ["Linux", "Darwin", "Windows"])
def test_each_platform_covers_core_diagnostics(system):
    names, _ = names_and_programs(system)
    for required in ("interfaces", "routes", "dns_lookup", "ping_ip", "traceroute"):
        assert required in names, f"{system} missing {required}"


def test_windows_uses_windows_tools_and_flags():
    cmds = dict(commands_for_platform("Windows"))
    assert cmds["interfaces"][0] == "ipconfig"
    assert cmds["routes"][:2] == ["route", "print"]
    assert cmds["ping_ip"][0] == "ping" and "-n" in cmds["ping_ip"] and "-c" not in cmds["ping_ip"]
    assert cmds["traceroute"][0] == "tracert"


def test_macos_uses_bsd_tools():
    cmds = dict(commands_for_platform("Darwin"))
    assert cmds["interfaces"][0] == "ifconfig"
    assert cmds["routes"][:2] == ["netstat", "-rn"]
    assert cmds["dns_config"][:2] == ["scutil", "--dns"]
    assert "-c" in cmds["ping_ip"]
    assert cmds["traceroute"][0] == "traceroute"


def test_linux_uses_iproute2():
    cmds = dict(commands_for_platform("Linux"))
    assert cmds["interfaces"][:2] == ["ip", "addr"]
    assert cmds["routes"][:2] == ["ip", "route"]


def test_unknown_platform_falls_back_to_posix_commands():
    names, _ = names_and_programs("FreeBSD")
    assert {"ping_ip", "dns_lookup"} <= names


def test_run_command_captures_output_of_real_process():
    out = run_command([sys.executable, "-c", "print('hello')"], timeout=10)
    assert out.returncode == 0
    assert "hello" in out.stdout
    assert out.error is None


def test_run_command_reports_missing_program_without_raising():
    out = run_command(["definitely-not-a-real-program-xyz"], timeout=5)
    assert out.returncode is None
    assert "not found" in out.error.lower()


def test_run_command_reports_timeout_without_raising():
    out = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert out.returncode is None
    assert "timed out" in out.error.lower()


def test_run_command_tolerates_undecodable_output():
    out = run_command([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff\\xfe ok')"], timeout=10)
    assert "ok" in out.stdout


def fake_runner(calls):
    def runner(argv, timeout):
        calls.append(argv)
        if argv[0] == "traceroute":
            return CommandOutput(None, "", "", "command not found: traceroute")
        return CommandOutput(0, f"output of {argv[0]}", "", None)
    return runner


def test_run_diagnostics_writes_text_and_json_logs(tmp_path):
    calls = []
    path = run_diagnostics(failing_health(), tmp_path, runner=fake_runner(calls), system="Darwin", now=FIXED_NOW)
    assert path.exists() and path.parent == tmp_path
    text = path.read_text(encoding="utf-8")
    assert "1.1.1.1:443 FAIL" in text
    assert "output of ifconfig" in text
    assert "command not found: traceroute" in text  # failures are logged, not fatal

    data = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
    assert data["platform"]["system"] == "Darwin"
    assert data["health"]["healthy"] is False
    assert {c["name"] for c in data["commands"]} >= {"interfaces", "traceroute"}
    assert calls  # commands were actually run


def test_log_filename_is_windows_safe_and_timestamped(tmp_path):
    path = run_diagnostics(failing_health(), tmp_path, runner=fake_runner([]), system="Windows", now=FIXED_NOW)
    assert "20261002T170405Z" in path.name
    for bad in '<>:"/\\|?*':
        assert bad not in path.name


def test_run_diagnostics_creates_missing_log_dir(tmp_path):
    target = tmp_path / "nested" / "logs"
    path = run_diagnostics(failing_health(), target, runner=fake_runner([]), system="Linux", now=FIXED_NOW)
    assert path.parent == target


def test_run_diagnostics_does_not_overwrite_existing_log(tmp_path):
    first = run_diagnostics(failing_health(), tmp_path, runner=fake_runner([]), system="Linux", now=FIXED_NOW)
    second = run_diagnostics(failing_health(), tmp_path, runner=fake_runner([]), system="Linux", now=FIXED_NOW)
    assert first != second and first.exists() and second.exists()


def test_run_diagnostics_survives_runner_exceptions(tmp_path):
    def exploding(argv, timeout):
        raise RuntimeError("boom")

    path = run_diagnostics(failing_health(), tmp_path, runner=exploding, system="Linux", now=FIXED_NOW)
    assert "boom" in path.read_text(encoding="utf-8")


def test_run_diagnostics_includes_python_level_dns_and_proxy_info(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8080")
    path = run_diagnostics(failing_health(), tmp_path, runner=fake_runner([]), system="Linux", now=FIXED_NOW)
    data = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
    assert "getaddrinfo" in data["python_checks"]
    assert data["python_checks"]["proxy_env"].get("HTTPS_PROXY") == "http://proxy.example:8080"


def test_proxy_credentials_are_redacted_in_logs(tmp_path, monkeypatch):
    userinfo = ":".join(["user", "s3cret"])
    monkeypatch.setenv("HTTP_PROXY", "http://" + userinfo + "@proxy.example:8080")
    path = run_diagnostics(failing_health(), tmp_path, runner=fake_runner([]), system="Linux", now=FIXED_NOW)
    assert "s3cret" not in path.read_text(encoding="utf-8")
    assert "s3cret" not in path.with_suffix(".json").read_text(encoding="utf-8")
    assert "proxy.example:8080" in path.read_text(encoding="utf-8")


def test_decode_falls_back_to_console_code_page_for_localized_output():
    raw = "Zeitüberschreitung der Anforderung".encode("cp850")
    assert diag_mod._decode(raw, fallback="cp850") == "Zeitüberschreitung der Anforderung"


def test_decode_prefers_utf8_when_valid():
    assert diag_mod._decode("héllo".encode("utf-8"), fallback="cp850") == "héllo"


def test_fallback_encoding_is_oem_on_windows():
    assert diag_mod._fallback_encoding(windows=True) == "oem"
    assert diag_mod._fallback_encoding(windows=False)  # some locale encoding


def test_decode_survives_unknown_fallback_codec():
    assert "ok" in diag_mod._decode(b"\xff ok", fallback="no-such-codec")


@pytest.mark.parametrize("value", [
    "user:" + "s3cret" + "@proxy.example:8080",                # no scheme
    "http://user:pa/" + "s3cret" + "@proxy.example:8080",      # '/' in password
    "socks5://" + "s3cret" + "@proxy.example:1080",
])
def test_redact_handles_schemeless_and_odd_passwords(value):
    out = diag_mod._redact(value)
    assert "s3cret" not in out
    assert "proxy.example" in out
