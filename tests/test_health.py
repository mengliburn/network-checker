import socket

from network_checker.health import DEFAULT_TARGETS, Target, check_health


def make_connector(results):
    """Fake connector: results maps (host, port) -> None (ok) or Exception."""
    calls = []

    def connect(host, port, timeout):
        calls.append((host, port, timeout))
        outcome = results.get((host, port))
        if isinstance(outcome, Exception):
            raise outcome

    connect.calls = calls
    return connect


def test_default_targets_use_reliable_public_providers():
    hosts = {t.host for t in DEFAULT_TARGETS}
    assert {"1.1.1.1", "8.8.8.8"} <= hosts
    assert len(DEFAULT_TARGETS) >= 3


def test_healthy_when_all_targets_reachable():
    targets = [Target("a", 1), Target("b", 2)]
    result = check_health(targets, connector=make_connector({}), timeout=2.0)
    assert result.healthy is True
    assert [r.ok for r in result.results] == [True, True]


def test_healthy_when_at_least_one_target_reachable():
    targets = [Target("a", 1), Target("b", 2)]
    connector = make_connector({("a", 1): socket.timeout("timed out")})
    result = check_health(targets, connector=connector)
    assert result.healthy is True
    assert result.results[0].ok is False
    assert "timed out" in result.results[0].error


def test_unhealthy_when_every_target_fails():
    targets = [Target("a", 1), Target("b", 2)]
    connector = make_connector({
        ("a", 1): OSError("Network is unreachable"),
        ("b", 2): socket.gaierror("Name or service not known"),
    })
    result = check_health(targets, connector=connector)
    assert result.healthy is False
    assert all(not r.ok for r in result.results)
    assert "unreachable" in result.results[0].error


def test_passes_timeout_to_connector():
    connector = make_connector({})
    check_health([Target("a", 1)], connector=connector, timeout=3.5)
    assert connector.calls == [("a", 1, 3.5)]


def test_records_latency_for_each_target():
    result = check_health([Target("a", 1)], connector=make_connector({}))
    assert result.results[0].latency_ms >= 0


def test_empty_target_list_is_unhealthy():
    assert check_health([], connector=make_connector({})).healthy is False


def test_result_summary_is_human_readable():
    connector = make_connector({("b", 2): OSError("refused")})
    result = check_health([Target("a", 1), Target("b", 2)], connector=connector)
    summary = result.summary()
    assert "a:1 OK" in summary
    assert "b:2 FAIL" in summary and "refused" in summary


def test_dns_failure_alone_makes_check_unhealthy():
    targets = [Target("1.1.1.1", 443), Target("8.8.8.8", 443), Target("www.google.com", 443)]
    connector = make_connector({("www.google.com", 443): socket.gaierror("Temporary failure in name resolution")})
    result = check_health(targets, connector=connector)
    assert result.dns_ok is False
    assert result.healthy is False
    assert "DNS" in result.summary()


def test_ip_only_targets_do_not_require_dns():
    result = check_health([Target("1.1.1.1", 443)], connector=make_connector({}))
    assert result.dns_ok is None
    assert result.healthy is True


def test_targets_are_checked_concurrently_within_a_deadline():
    import threading
    import time

    release = threading.Event()

    def blocking(host, port, timeout):
        if host == "hang":
            release.wait(10)  # simulates resolver ignoring the timeout
            raise OSError("never")

    try:
        start = time.monotonic()
        result = check_health([Target("hang", 1), Target("1.1.1.1", 2)], connector=blocking, timeout=0.3)
        elapsed = time.monotonic() - start
    finally:
        release.set()
    assert elapsed < 2
    hung = result.results[0]
    assert hung.ok is False and "Timeout" in hung.error
    assert result.results[1].ok is True
