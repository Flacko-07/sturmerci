# SPDX-License-Identifier: Apache-2.0
"""Gate 3: strict model output contract."""
import pytest
from pydantic import ValidationError

from sentinel.models.contracts import FindingTriageOutput


def _valid_payload(**overrides):
    base = {
        "task_type": "finding_triage",
        "summary": "Candidate finding, not yet validated",
        "candidate_category": "access_control",
        "possible_references": ["CWE-284", "API1:2023"],
        "evidence_ids": ["ev_" + "a" * 16],
        "missing_evidence": ["Need second authorized test role"],
        "confidence_hint": "low",
        "recommended_next_step": "Human review of evidence and policy",
    }
    base.update(overrides)
    return base


def test_valid_payload_parses():
    FindingTriageOutput.model_validate(_valid_payload())


def test_extra_field_rejected():
    with pytest.raises(ValidationError):
        FindingTriageOutput.model_validate(
            _valid_payload(unexpected="should fail")
        )


def test_severity_field_rejected():
    with pytest.raises(ValidationError):
        FindingTriageOutput.model_validate(
            _valid_payload(severity="critical")
        )


def test_validation_status_field_rejected():
    with pytest.raises(ValidationError):
        FindingTriageOutput.model_validate(
            _valid_payload(validation_status="confirmed")
        )


def test_scope_allowed_field_rejected():
    with pytest.raises(ValidationError):
        FindingTriageOutput.model_validate(
            _valid_payload(scope_allowed=True)
        )


def test_evidence_id_format_enforced():
    with pytest.raises(ValidationError):
        FindingTriageOutput.model_validate(
            _valid_payload(evidence_ids=["not-a-valid-id"])
        )


def test_cwe_reference_format_enforced():
    with pytest.raises(ValidationError):
        FindingTriageOutput.model_validate(
            _valid_payload(possible_references=["CWE access control"])
        )
