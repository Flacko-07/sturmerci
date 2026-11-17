# SPDX-License-Identifier: Apache-2.0
"""Unit tests for Subfinder parsing and validation. No root needed."""

from sentinel.adapters.subfinder import (
    parse_output,
    validate_result_host,
)


# --- parse_output ---


def test_parse_valid_json_lines():
    stdout = (
        '{"host":"a.probe.test","input":"probe.test","source":"crtsh"}\n'
        '{"host":"b.probe.test","input":"probe.test","source":"crtsh"}\n'
    )
    findings = parse_output(stdout)
    assert len(findings) == 2
    assert findings[0].host == "a.probe.test"
    assert findings[0].source == "crtsh"


def test_parse_empty_returns_empty():
    assert parse_output("") == []
    assert parse_output("\n\n\n") == []


def test_parse_skips_malformed_lines():
    stdout = (
        '{"host":"a.probe.test","input":"probe.test","source":"crtsh"}\n'
        "not json at all\n"
        '{"incomplete": "json"\n'
        '{"host":"b.probe.test","input":"probe.test","source":"crtsh"}\n'
    )
    findings = parse_output(stdout)
    assert len(findings) == 2


def test_parse_skips_non_dict():
    stdout = '["array", "not", "dict"]\n{"host":"x.test","input":"y","source":"z"}\n'
    findings = parse_output(stdout)
    assert len(findings) == 1
    assert findings[0].host == "x.test"


def test_parse_skips_missing_host():
    stdout = '{"input":"probe.test","source":"crtsh"}\n'
    findings = parse_output(stdout)
    assert findings == []


def test_parse_skips_empty_host():
    stdout = '{"host":"","input":"probe.test","source":"crtsh"}\n'
    findings = parse_output(stdout)
    assert findings == []


# --- validate_result_host ---


def test_valid_subdomain():
    ok, reason = validate_result_host("mail.probe.test", "probe.test")
    assert ok is True and reason is None


def test_valid_deep_subdomain():
    ok, _ = validate_result_host("api.staging.probe.test", "probe.test")
    assert ok is True


def test_apex_accepted():
    ok, _ = validate_result_host("probe.test", "probe.test")
    assert ok is True


def test_different_domain_rejected():
    ok, reason = validate_result_host("evil.com", "probe.test")
    assert ok is False
    assert "not_subdomain_of" in reason


def test_suffix_confusion_rejected():
    # notprobe.test is not a subdomain of probe.test
    ok, reason = validate_result_host("notprobe.test", "probe.test")
    assert ok is False


def test_wildcard_rejected():
    ok, reason = validate_result_host("*.probe.test", "probe.test")
    assert ok is False
    assert reason == "wildcard"


def test_uppercase_normalized():
    # uppercase gets lowercased before the domain check
    ok, _ = validate_result_host("Mail.Probe.Test", "probe.test")
    assert ok is True


def test_trailing_dot_normalized():
    ok, _ = validate_result_host("mail.probe.test.", "probe.test")
    assert ok is True


def test_invalid_hostname_chars_rejected():
    ok, reason = validate_result_host("bad_host.probe.test", "probe.test")
    assert ok is False
    assert reason == "invalid_hostname"
