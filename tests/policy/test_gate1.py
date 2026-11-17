# SPDX-License-Identifier: Apache-2.0
"""Gate 1: URL canonicalization + wildcard scope matching."""

import pytest

from sentinel.scope.canonicalizer import (
    canonicalize_url,
    is_safe_wildcard,
    CanonicalizationError,
)
from sentinel.scope.matcher import hostname_in_scope, url_in_scope

SCOPES = [
    {"type": "hostname", "value": "app.example.test"},
    {"type": "wildcard_hostname", "value": "*.api.example.test"},
]


def test_userinfo_confusion_denied():
    u = canonicalize_url("https://app.example.test@evil.test/path")
    assert u.hostname == "evil.test"
    assert url_in_scope(u, SCOPES) is False


def test_decimal_ipv4_canonicalized():
    u = canonicalize_url("https://2130706433/")
    assert u.hostname == "127.0.0.1"


def test_trailing_dot_normalized():
    u = canonicalize_url("https://app.example.test./")
    assert u.hostname == "app.example.test"
    assert url_in_scope(u, SCOPES) is True


def test_default_port_stripped():
    a = canonicalize_url("https://app.example.test/")
    b = canonicalize_url("https://app.example.test:443/")
    assert a == b


def test_wildcard_excludes_apex():
    assert hostname_in_scope("api.example.test", SCOPES) is False
    assert hostname_in_scope("app.example.test", SCOPES) is True


def test_wildcard_one_label_only():
    assert hostname_in_scope("v1.api.example.test", SCOPES) is True
    assert hostname_in_scope("a.b.api.example.test", SCOPES) is False


def test_suffix_confusion_denied():
    assert hostname_in_scope("notapp.example.test", SCOPES) is False
    assert hostname_in_scope("app.example.test.evil.test", SCOPES) is False


def test_unsafe_wildcards_rejected():
    assert is_safe_wildcard("*.com") is False
    assert is_safe_wildcard("*.co.uk") is False
    assert is_safe_wildcard("*.example.com") is True
    assert is_safe_wildcard("*.api.example.com") is True


def test_control_chars_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize_url("https://app.example.test/\x00")


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://app.example.test/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,x",
        "gopher://app.example.test/",
    ],
)
def test_unsupported_schemes_rejected(raw):
    with pytest.raises(CanonicalizationError):
        canonicalize_url(raw)
