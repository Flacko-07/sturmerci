# SPDX-License-Identifier: Apache-2.0
"""Unit tests for Gitleaks report parsing/validation."""

import json

import pytest

from sentinel.adapters.gitleaks import (
    parse_and_validate,
    GitleaksOutputError,
    REDACTED,
    REQUIRED_FIELDS,
)


def _valid_finding(**overrides):
    base = {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "a.py",
        "StartLine": 1,
        "EndLine": 1,
        "StartColumn": 1,
        "EndColumn": 20,
        "Match": REDACTED,
        "Secret": REDACTED,
        "Entropy": 4.0,
        "Author": "",
        "Email": "",
        "Date": "",
        "Commit": "",
        "Message": "",
        "SymlinkFile": "",
        "Tags": [],
        "Fingerprint": "a.py:aws-access-token:1",
    }
    base.update(overrides)
    return base


def _dump(findings):
    return json.dumps(findings).encode()


def test_empty_array_ok():
    assert parse_and_validate(b"[]") == []


def test_empty_bytes_returns_empty():
    assert parse_and_validate(b"") == []


def test_single_valid_finding():
    out = parse_and_validate(_dump([_valid_finding()]))
    assert len(out) == 1
    assert out[0]["RuleID"] == "aws-access-token"


def test_non_json_raises():
    with pytest.raises(GitleaksOutputError, match="not valid JSON"):
        parse_and_validate(b"not json")


def test_non_array_top_level_raises():
    with pytest.raises(GitleaksOutputError, match="must be an array"):
        parse_and_validate(b'{"a": 1}')


def test_non_object_finding_raises():
    with pytest.raises(GitleaksOutputError, match="is not an object"):
        parse_and_validate(b'["not an object"]')


def test_missing_field_raises():
    f = _valid_finding()
    del f["Fingerprint"]
    with pytest.raises(GitleaksOutputError, match="missing required fields"):
        parse_and_validate(_dump([f]))


@pytest.mark.parametrize("field", ["RuleID", "Description", "Secret", "Match"])
def test_critical_fields_required(field):
    f = _valid_finding()
    del f[field]
    with pytest.raises(GitleaksOutputError, match="missing required fields"):
        parse_and_validate(_dump([f]))


def test_unredacted_secret_rejected():
    f = _valid_finding(Secret="AKIAIOSFODNN7EXAMPLE")
    with pytest.raises(GitleaksOutputError, match="Secret not redacted"):
        parse_and_validate(_dump([f]))


def test_unredacted_match_rejected():
    f = _valid_finding(Match="prefix AKIA... suffix")
    with pytest.raises(GitleaksOutputError, match="Match not redacted"):
        parse_and_validate(_dump([f]))


def test_all_required_fields_present():
    # Sanity: _valid_finding has exactly the fields we require
    assert set(_valid_finding().keys()) == REQUIRED_FIELDS
