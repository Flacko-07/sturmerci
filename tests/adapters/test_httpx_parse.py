# SPDX-License-Identifier: Apache-2.0
"""Unit tests for httpx adapter. No root needed."""

import pytest

from sentinel.adapters.httpx import (
    build_argv,
    parse_output,
    _assert_no_forbidden_flags,
    HttpxAdapterError,
    FORBIDDEN_FLAGS,
    _validate_observation,
    WebEndpointObservation,
)


# --- build_argv ---


def test_build_argv_https_get():
    argv = build_argv("/usr/bin/httpx", "app.example.com", 443, "https", "GET")
    assert argv[0] == "/usr/bin/httpx"
    assert "-u" in argv
    assert "https://app.example.com:443/" in argv
    assert "-silent" in argv
    assert "-json" in argv
    assert "-nc" in argv
    assert "-duc" in argv


def test_build_argv_no_path_flag():
    argv = build_argv("/h", "x.test", 443, "https", "GET")
    for a in argv:
        assert a not in ("-path", "-paths"), f"unexpected flag: {a}"


def test_build_argv_head_allowed():
    build_argv("/h", "x.test", 443, "https", "HEAD")


@pytest.mark.parametrize("bad", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_build_argv_bad_method_rejected(bad):
    with pytest.raises(HttpxAdapterError, match="method"):
        build_argv("/h", "x.test", 443, "https", bad)


def test_build_argv_bad_scheme():
    with pytest.raises(HttpxAdapterError, match="scheme"):
        build_argv("/h", "x.test", 443, "ftp", "GET")


def test_build_argv_bad_port():
    with pytest.raises(HttpxAdapterError, match="port"):
        build_argv("/h", "x.test", 0, "https", "GET")
    with pytest.raises(HttpxAdapterError, match="port"):
        build_argv("/h", "x.test", 65536, "https", "GET")


def test_build_argv_bad_hostname():
    for bad in ("bad_host.test", "-bad.test", ".bad", ""):
        with pytest.raises(HttpxAdapterError, match="hostname"):
            build_argv("/h", bad, 443, "https", "GET")


# --- forbidden flags ---


@pytest.mark.parametrize("flag", FORBIDDEN_FLAGS)
def test_forbidden_flags_rejected(flag):
    with pytest.raises(HttpxAdapterError, match="forbidden"):
        _assert_no_forbidden_flags(["/h", flag, "x.test"])


def test_forbidden_flag_with_value_rejected():
    with pytest.raises(HttpxAdapterError, match="forbidden"):
        _assert_no_forbidden_flags(["/h", "-path=/api", "x.test"])


# --- parse_output ---

VALID_LINE = (
    '{"timestamp":"2026-11-14T00:00:00Z","port":"443",'
    '"url":"https://app.example.com:443","input":"app.example.com",'
    '"title":"App","scheme":"https","webserver":"nginx",'
    '"tech":["nginx","React"],"status_code":200,'
    '"tls":{"subject_cn":"app.example.com","issuer_cn":"Lets Encrypt",'
    '"dns_names":["app.example.com","www.app.example.com"]}}'
)


def test_parse_single_valid():
    findings = parse_output(VALID_LINE)
    assert len(findings) == 1
    f = findings[0]
    assert f.url == "https://app.example.com:443"
    assert f.port == 443
    assert f.scheme == "https"
    assert f.status_code == 200
    assert f.webserver == "nginx"
    assert "React" in f.tech
    assert f.tls_subject_cn == "app.example.com"
    assert "www.app.example.com" in f.tls_dns_names


def test_parse_empty():
    assert parse_output("") == []
    assert parse_output("\n\n") == []


def test_parse_skips_malformed():
    text = VALID_LINE + "\n" + "not json\n" + VALID_LINE
    findings = parse_output(text)
    assert len(findings) == 2


def test_parse_skips_missing_url():
    text = '{"title":"no url","port":"443"}\n'
    assert parse_output(text) == []


def test_parse_handles_status_code_as_int_or_string():
    text = (
        '{"url":"https://a.test:443","port":"443","scheme":"https","status-code":200}\n'
    )
    findings = parse_output(text)
    assert len(findings) == 1
    assert findings[0].status_code == 200


def test_validate_observation_ok():
    obs = WebEndpointObservation(
        url="https://app.example.com:443",
        input_url="app.example.com",
        port=443,
        scheme="https",
        status_code=200,
        title="",
        webserver="",
        tech=(),
        tls_subject_cn="",
        tls_issuer="",
        tls_dns_names=(),
    )
    ok, _ = _validate_observation(obs, "app.example.com", 443, "https")
    assert ok


def test_validate_observation_wrong_host():
    obs = WebEndpointObservation(
        url="https://other.test:443",
        input_url="",
        port=443,
        scheme="https",
        status_code=200,
        title="",
        webserver="",
        tech=(),
        tls_subject_cn="",
        tls_issuer="",
        tls_dns_names=(),
    )
    ok, reason = _validate_observation(obs, "app.example.com", 443, "https")
    assert not ok
    assert "host_mismatch" in reason


def test_validate_observation_wrong_port():
    obs = WebEndpointObservation(
        url="https://app.example.com:8443",
        input_url="",
        port=8443,
        scheme="https",
        status_code=200,
        title="",
        webserver="",
        tech=(),
        tls_subject_cn="",
        tls_issuer="",
        tls_dns_names=(),
    )
    ok, reason = _validate_observation(obs, "app.example.com", 443, "https")
    assert not ok
    assert "port_mismatch" in reason


# --- M7-02: path validation ---


def test_m7p02_observation_path_root_accepted():
    obs = WebEndpointObservation(
        url="https://app.example.com:443/",
        input_url="",
        port=443,
        scheme="https",
        status_code=200,
        title="",
        webserver="",
        tech=(),
        tls_subject_cn="",
        tls_issuer="",
        tls_dns_names=(),
    )
    ok, _ = _validate_observation(obs, "app.example.com", 443, "https")
    assert ok


def test_m7p02_observation_path_different_rejected():
    obs = WebEndpointObservation(
        url="https://app.example.com:443/admin",
        input_url="",
        port=443,
        scheme="https",
        status_code=200,
        title="",
        webserver="",
        tech=(),
        tls_subject_cn="",
        tls_issuer="",
        tls_dns_names=(),
    )
    ok, reason = _validate_observation(obs, "app.example.com", 443, "https")
    assert not ok
    assert "path_mismatch" in reason


# --- M7-03: strict port parsing ---


def test_m7p03_non_numeric_port_skipped():
    line = (
        '{"url":"https://a.test:443","port":"not-a-number",'
        '"scheme":"https","status_code":200}\n'
    )
    assert parse_output(line) == []


def test_m7p03_out_of_range_port_skipped():
    line = (
        '{"url":"https://a.test:443","port":"999999",'
        '"scheme":"https","status_code":200}\n'
    )
    assert parse_output(line) == []


def test_m7p03_good_line_after_bad_line_survives():
    text = (
        '{"url":"https://a.test:443","port":"not-a-number"}\n'
        '{"url":"https://b.test:443","port":"443","scheme":"https"}\n'
    )
    findings = parse_output(text)
    assert len(findings) == 1
    assert findings[0].url == "https://b.test:443"
