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


def test_non_dns_failure_on_hostname_target_is_not_reported_as_dns_failure():
    targets = [Target("1.1.1.1", 443), Target("www.google.com", 443)]
    connector = make_connector({("www.google.com", 443): ConnectionRefusedError("refused")})
    result = check_health(targets, connector=connector)
    assert result.results[1].dns_failure is False
    assert result.dns_ok is not False
    assert result.healthy is True
    assert "DNS" not in result.summary()


def test_gaierror_is_classified_as_dns_failure():
    connector = make_connector({("www.google.com", 443): socket.gaierror(-3, "Temporary failure")})
    result = check_health([Target("www.google.com", 443)], connector=connector)
    assert result.results[0].dns_failure is True


def test_dns_ok_true_when_any_hostname_target_connects():
    connector = make_connector({("a.example", 1): socket.gaierror("x")})
    result = check_health([Target("a.example", 1), Target("b.example", 2)], connector=connector)
    assert result.dns_ok is True


# ---- real default connector (TLS, shared deadline across addresses) ----

import threading as _threading

from network_checker import health as health_mod


def _serve_once(handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        try:
            conn, _ = srv.accept()
            with conn:
                handler(conn)
        except OSError:
            pass
        finally:
            srv.close()

    _threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def test_default_connector_verifies_tls_so_captive_portals_fail():
    # A captive portal / transparent proxy accepts TCP but cannot present a
    # valid certificate for the real host.
    port = _serve_once(lambda conn: conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://portal/\r\n\r\n"))
    import pytest
    with pytest.raises(OSError):  # ssl.SSLError is an OSError
        health_mod.tls_connect("127.0.0.1", port, 3.0)


def test_default_connector_shares_one_deadline_across_resolved_addresses(monkeypatch):
    import time

    attempts = []

    def fake_getaddrinfo(host, port, *a, **k):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", port, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port)),
        ]

    def fake_attempt(family, addr, timeout):
        attempts.append((addr[0], timeout))
        time.sleep(timeout)  # every address hangs until its timeout
        raise socket.timeout("timed out")

    monkeypatch.setattr(health_mod.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(health_mod, "_connect_addr", fake_attempt)
    import pytest
    start = time.monotonic()
    with pytest.raises(OSError):
        health_mod.tls_connect("example.com", 443, 0.6)
    # IPv4 first, and a hanging IPv4 address must not starve the IPv6 one
    assert [a for a, _ in attempts] == ["192.0.2.1", "2001:db8::1"]
    assert time.monotonic() - start < 1.0


def test_slow_dns_resolution_is_bounded_and_classified_as_dns_failure(monkeypatch):
    import time

    def hanging_getaddrinfo(*a, **k):
        time.sleep(5)
        return []

    monkeypatch.setattr(health_mod.socket, "getaddrinfo", hanging_getaddrinfo)
    import pytest
    start = time.monotonic()
    with pytest.raises(socket.gaierror):
        health_mod.tls_connect("example.com", 443, 0.5)
    assert time.monotonic() - start < 2


def test_default_connector_is_tls():
    import inspect
    assert inspect.signature(check_health).parameters["connector"].default is health_mod.tls_connect
