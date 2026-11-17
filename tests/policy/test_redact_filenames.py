# SPDX-License-Identifier: Apache-2.0
"""Regression: unknown_long_token must not redact file paths.

Live end-to-end run caught this: a 45-char path like
`engagements/eng_x/source/_helpers.py` matched `_UNKNOWN_LONG_TOKEN`
because the character class includes `/`. Redaction produced
`[REDACTED:unknown_long_token].py` — the `.py` survived as suffix —
making every bandit artifact held_for_review.

Behavior contract:
  - A path WITH a known code-file extension (`.py`, `.js`, ...) → NOT
    redacted by the unknown-token rule.
  - A path WITHOUT a known extension → still redacted by the unknown-
    token rule (conservative: no way to tell a 45-char no-extension
    token from a secret).
  - Actual secrets (AWS keys, JWTs, base64) → caught by their
    respective rules regardless.

Tests below use `redact()` (applies ALL rules) for the secret cases so
they test the pipeline contract, not one rule in isolation.
"""
from __future__ import annotations

import pytest

from sentinel.evidence.redact import redact


# --- 1. Extension-suffixed paths must not trigger unknown_format ---

@pytest.mark.parametrize("path", [
    "engagements/eng_c33daa9e22f14b40/source/_helpers.py",
    "engagements/eng_c33daa9e22f14b40/source/adapters_metasploit.py",
    "/usr/local/lib/python3.12/site-packages/sentinel/adapters/zap.py",
    "src/sentinel/evidence/redact.py",
    "config/wordlists/common.txt",
    "/tmp/sentinel-nuclei-home-abc123/.config/nuclei.json",
    "path/to/some/very_long_directory_name_that_exceeds_forty_chars.go",
    "root/very/deeply/nested/file/that/is/long_enough/marker.yaml",
])
def test_redact_preserves_extensioned_paths(path):
    """Extension-suffixed paths are NOT secrets — must not trigger hold."""
    payload = f'{{"SourceFile": "{path}", "result": "ok"}}'
    sanitized, record = redact(payload)
    assert not record.unknown_format_triggered, (
        f"filename {path!r} triggered unknown_format — "
        f"path with known extension is not a secret"
    )
    assert sanitized == payload, (
        f"filename {path!r} was modified: {sanitized!r}"
    )


# --- 2. Secrets still caught (via the full redact pipeline) ---

@pytest.mark.parametrize("secret,rule_hint", [
    ("AKIA" + "A" * 16, "aws_access_key"),
    ("ghp_" + "a" * 40, "github_token"),
    (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123xyz",
        "jwt",
    ),
    ("aB3+/xyz" * 6, "unknown_long_token"),  # 48 base64-shaped chars
])
def test_redact_still_catches_real_secrets(secret, rule_hint):
    """Filename exclusion must not weaken real-secret detection."""
    text = f'{{"key": "{secret}"}}'
    sanitized, record = redact(text)
    assert secret not in sanitized, (
        f"secret {secret[:20]}... survived redaction "
        f"(expected rule: {rule_hint})"
    )
    assert any(record.rules_applied.values()), (
        f"no redaction rule fired for {rule_hint} — rule regression"
    )


# --- 3. No-extension tokens still caught (conservative) ---

def test_redact_catches_no_extension_long_token():
    """A 45+ char no-extension token is still redacted — no way to
    distinguish it from a secret by shape alone."""
    token = "engagements/eng_c33daa9e22f14b40/source/_helpers"
    text = f'{{"path": "{token}"}}'
    sanitized, record = redact(text)
    assert token not in sanitized, (
        f"no-extension path survived — should be conservatively redacted"
    )
    assert record.unknown_format_triggered, (
        f"no-extension long token did not trigger unknown_format"
    )
