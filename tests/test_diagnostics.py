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


def test_run_command_timeout_kills_whole_process_tree(tmp_path):
    import time
    heartbeat = tmp_path / "beat.txt"
    grandchild = (
        "import time, sys\n"
        "p = sys.argv[1]\n"
        "while True:\n"
        "    open(p, 'a').write('x'); time.sleep(0.05)\n"
    )
    child = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}, {str(heartbeat)!r}])\n"
        "time.sleep(60)\n"
    )
    start = time.monotonic()
    out = run_command([sys.executable, "-c", child], timeout=1.5)
    assert time.monotonic() - start < 15
    assert "timed out" in out.error
    time.sleep(0.5)
    size = heartbeat.stat().st_size if heartbeat.exists() else 0
    time.sleep(1.0)
    after = heartbeat.stat().st_size if heartbeat.exists() else 0
    assert after == size, "grandchild process survived the timeout"


def test_run_command_returns_when_child_exits_even_if_grandchild_keeps_output_open():
    import time
    grandchild = "import time; time.sleep(30)"
    child = (
        "import subprocess, sys\n"
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}])\n"
        "print('child done', flush=True)\n"
    )
    start = time.monotonic()
    out = run_command([sys.executable, "-c", child], timeout=25)
    assert time.monotonic() - start < 10
    assert out.returncode == 0 and out.error is None
    assert "child done" in out.stdout


def test_ctrl_c_interrupts_a_running_command_promptly_and_kills_it(tmp_path):
    import _thread
    import threading
    import time
    marker = tmp_path / "alive.txt"
    code = (
        "import time, sys\n"
        "while True:\n"
        f"    open({str(marker)!r}, 'a').write('x'); time.sleep(0.05)\n"
    )
    timer = threading.Timer(0.7, _thread.interrupt_main)
    timer.start()
    start = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        run_command([sys.executable, "-c", code], timeout=60)
    assert time.monotonic() - start < 10
    time.sleep(0.5)
    size = marker.stat().st_size if marker.exists() else 0
    time.sleep(0.8)
    assert (marker.stat().st_size if marker.exists() else 0) == size, "child survived Ctrl+C"


def test_windows_child_shares_console_group_so_it_receives_ctrl_c(monkeypatch):
    captured = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            captured.update(kw)
            raise FileNotFoundError

    monkeypatch.setattr(diag_mod.os, "name", "nt")
    monkeypatch.setattr(diag_mod.subprocess, "Popen", FakePopen)
    run_command(["x"], timeout=1)
    assert "creationflags" not in captured and "start_new_session" not in captured


def test_large_output_keeps_head_and_tail_with_truncation_marker(monkeypatch):
    monkeypatch.setattr(diag_mod, "MAX_OUTPUT_BYTES", 1000)
    code = "import sys; sys.stdout.write('HEAD' + 'x' * 5000 + 'FINAL-DIAGNOSIS')"
    out = run_command([sys.executable, "-c", code], timeout=30)
    assert out.stdout.startswith("HEAD")
    assert out.stdout.endswith("FINAL-DIAGNOSIS")
    assert "truncated" in out.stdout
    assert len(out.stdout) < 1200


def test_small_output_is_not_marked_truncated():
    out = run_command([sys.executable, "-c", "print('hi')"], timeout=30)
    assert "truncated" not in out.stdout


@pytest.mark.parametrize("limit", [1000, 1001, 1002, 1003])
def test_truncation_cuts_on_utf8_character_boundaries(monkeypatch, limit):
    monkeypatch.setattr(diag_mod, "MAX_OUTPUT_BYTES", limit)
    code = "import sys; sys.stdout.buffer.write(('é€' * 2000).encode('utf-8'))"
    out = run_command([sys.executable, "-c", code], timeout=30)
    assert "\ufffd" not in out.stdout
    body = out.stdout.replace("\n", "")
    head, _, tail = body.partition("[")
    assert set(head) <= {"é", "€"} and head
    assert set(tail.split("]")[-1]) <= {"é", "€"}


SAMPLE = "aé€😀" * 3  # 1-, 2-, 3- and 4-byte UTF-8 characters


@pytest.mark.parametrize("cut", range(len(SAMPLE.encode("utf-8")) + 1))
def test_trim_helpers_produce_valid_utf8_for_every_cut(cut):
    data = SAMPLE.encode("utf-8")
    head = diag_mod._trim_partial_utf8_end(data[:cut])
    tail = diag_mod._trim_partial_utf8_start(data[cut:])
    head.decode("utf-8")  # strict: must not raise
    tail.decode("utf-8")
    assert data.startswith(head) and data.endswith(tail)
    assert cut - len(head) <= 3 and (len(data) - cut) - len(tail) <= 3  # at most one char lost


def test_trim_helpers_leave_non_utf8_codepage_output_alone():
    oem = "Zeitüberschreitung".encode("cp850")
    assert diag_mod._trim_partial_utf8_start(oem) == oem
    assert diag_mod._trim_partial_utf8_end(oem) == oem
