# SPDX-License-Identifier: Apache-2.0
"""Batch C.2: Host header authority parsing.

The reviewer's finding: proxy stripped :port before comparing Host to
the CONNECT authority, so CONNECT example.com:443 with
Host: example.com:8443 passed. These tests exercise the parser that
made the fix possible.
"""
from __future__ import annotations

import pytest

from sentinel.l7.proxy import _parse_host_header


def test_plain_dns_no_port():
    assert _parse_host_header("example.com") == ("example.com", None)


def test_dns_with_explicit_port():
    assert _parse_host_header("example.com:443") == ("example.com", 443)
    assert _parse_host_header("example.com:8443") == ("example.com", 8443)


def test_uppercase_normalised():
    assert _parse_host_header("EXAMPLE.COM:443") == ("example.com", 443)


def test_trailing_dot():
    # Not stripped by the parser — used as-is so callers decide
    assert _parse_host_header("example.com.:443") == ("example.com.", 443)


def test_ipv4():
    assert _parse_host_header("127.0.0.1") == ("127.0.0.1", None)
    assert _parse_host_header("127.0.0.1:8080") == ("127.0.0.1", 8080)


def test_ipv6_bracket_no_port():
    assert _parse_host_header("[::1]") == ("::1", None)


def test_ipv6_bracket_with_port():
    assert _parse_host_header("[::1]:443") == ("::1", 443)
    assert _parse_host_header("[2001:db8::1]:8443") == ("2001:db8::1", 8443)


def test_ipv6_bracket_unterminated():
    with pytest.raises(ValueError, match="unterminated"):
        _parse_host_header("[::1")


def test_ipv6_garbage_after_bracket():
    with pytest.raises(ValueError, match="garbage"):
        _parse_host_header("[::1]xyz")


def test_empty_host_rejected():
    with pytest.raises(ValueError, match="empty"):
        _parse_host_header("")
    with pytest.raises(ValueError, match="empty"):
        _parse_host_header("   ")


def test_non_numeric_port_rejected():
    with pytest.raises(ValueError, match="non-numeric"):
        _parse_host_header("example.com:abc")
    with pytest.raises(ValueError, match="non-numeric"):
        _parse_host_header("[::1]:abc")


def test_port_out_of_range_rejected():
    with pytest.raises(ValueError, match="out of range"):
        _parse_host_header("example.com:0")
    with pytest.raises(ValueError, match="out of range"):
        _parse_host_header("example.com:70000")
    with pytest.raises(ValueError, match="out of range"):
        _parse_host_header("[::1]:0")


def test_empty_hostname_with_port_rejected():
    with pytest.raises(ValueError, match="empty hostname"):
        _parse_host_header(":443")


def test_empty_ipv6_hostname_rejected():
    with pytest.raises(ValueError, match="empty IPv6"):
        _parse_host_header("[]")
    with pytest.raises(ValueError, match="empty IPv6"):
        _parse_host_header("[]:443")


def test_whitespace_stripped():
    assert _parse_host_header("  example.com:443  ") == ("example.com", 443)
