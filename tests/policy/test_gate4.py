# SPDX-License-Identifier: Apache-2.0
"""Gate 4: redaction fires before prompt assembly."""
import pytest

from sentinel.evidence.redact import (
    redact,
    assert_no_known_secrets,
)

AWS = "AKIAIOSFODNN7EXAMPLE"
GH  = "ghp_" + "A" * 36
JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0In0", "abc-_def123"])
EMAIL = "analyst@example.com"


def test_aws_key_redacted():
    text = f"export AWS_ACCESS_KEY_ID={AWS} and run"
    out, rec = redact(text)
    assert AWS not in out
    assert rec.rules_applied.get("aws_access_key", 0) == 1


def test_github_token_redacted():
    out, rec = redact(f"token={GH}")
    assert GH not in out
    assert rec.rules_applied.get("github_token", 0) == 1


def test_jwt_redacted():
    out, rec = redact(f"Authorization: Bearer {JWT}")
    # jwt rule OR auth_header rule may fire; at least one must
    assert JWT not in out
    assert rec.rules_applied.get("jwt", 0) + rec.rules_applied.get("auth_header", 0) >= 1


def test_cookie_header_redacted():
    out, rec = redact("Cookie: session=abcdef1234567890; csrftoken=zzz")
    assert "session=abcdef1234567890" not in out
    assert rec.rules_applied.get("cookie_header", 0) == 1


def test_email_redacted():
    out, _ = redact(f"Contact {EMAIL} for access")
    assert EMAIL not in out


def test_unknown_long_token_replaced_and_flagged():
    # 50-char token that matches no known rule
    unknown = "Zx" + "9" * 48
    out, rec = redact(f"custom_key={unknown}")
    assert unknown not in out
    assert rec.unknown_format_triggered is True
    assert rec.rules_applied.get("unknown_long_token", 0) >= 1


def test_audit_record_contains_no_secret_values():
    out, rec = redact(f"AKIA key {AWS} and {EMAIL}")
    # The record's string form must never contain the secret material
    s = repr(rec.rules_applied) + repr(rec.unknown_format_triggered)
    assert AWS not in s
    assert EMAIL not in s


def test_assert_no_known_secrets_fires_on_missed_secret():
    with pytest.raises(RuntimeError):
        assert_no_known_secrets(f"still has {AWS}")


def test_assert_no_known_secrets_passes_on_clean_text():
    assert_no_known_secrets("harmless content with no secrets")
