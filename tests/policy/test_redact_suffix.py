# SPDX-License-Identifier: Apache-2.0
"""REDACTED-suffix rule (Gate 4, Gitleaks context-preserving redaction).

Gitleaks 8.30.1 --redact preserves the last few characters of some secrets
in the Match field (e.g. "REDACTEDkP4"). The redacted_suffix rule collapses
those to a placeholder so no fragment reaches the evidence store.
"""

from sentinel.evidence.redact import redact


def test_redacted_suffix_collapsed_and_fragment_removed():
    out, rec = redact("prefix REDACTEDkP4 suffix")
    # Placeholder inserted (matches the rest of the redaction rules)
    assert "[REDACTED:redacted_suffix]" in out
    # The critical security property: no fragment of the secret survives
    assert "kP4" not in out
    # Context around the match is preserved
    assert out.startswith("prefix ")
    assert out.endswith(" suffix")
    assert rec.rules_applied.get("redacted_suffix", 0) == 1


def test_redacted_bare_unchanged():
    # "REDACTED" with no suffix (followed by a quote or whitespace) does not
    # match the rule, so it survives — this is intended: it's already a
    # redaction marker, not a secret fragment.
    out, rec = redact('AWS_SECRET_ACCESS_KEY = "REDACTED"')
    assert "REDACTED" in out
    assert rec.rules_applied.get("redacted_suffix", 0) == 0


def test_redacted_at_end_of_string_unchanged():
    out, _ = redact('...CCESS_KEY_ID     = "REDACTED')
    assert out.endswith("REDACTED")


def test_no_false_positive_on_redacted_marker_in_prose():
    # "REDACTED" followed by whitespace is not a fingerprint; leave it alone
    out, rec = redact("the field was REDACTED by the pipeline")
    assert "REDACTED" in out
    assert rec.rules_applied.get("redacted_suffix", 0) == 0


def test_suffix_with_digits_and_underscore_also_collapsed():
    out, rec = redact("note REDACTED_aB12 end")
    assert "[REDACTED:redacted_suffix]" in out
    assert "_aB12" not in out
    assert rec.rules_applied.get("redacted_suffix", 0) == 1
