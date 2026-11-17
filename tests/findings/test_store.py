# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence
from sentinel.findings import FindingError, FindingStore
from sentinel.llm import client as client_mod
from sentinel.storage.db import Database
from sentinel.triage.pipeline import triage_artifact


def _model_response(evidence_id: str) -> str:
    return json.dumps({
        "task_type": "finding_triage",
        "summary": "Potential issue for review",
        "candidate_category": "misconfiguration",
        "possible_references": [],
        "evidence_ids": [evidence_id],
        "missing_evidence": [],
        "confidence_hint": "medium",
        "recommended_next_step": "Review the evidence manually",
    })


@pytest.fixture
def finding_env(tmp_path, monkeypatch):
    client_mod._reset_circuit_for_tests()
    db = Database(tmp_path / "sentinel.sqlite3")
    engagement = EngagementStore(db).create(
        platform="lab", program_name="finding-test", policy_url=None,
        actor="operator", engagements_root=tmp_path / "engagements",
    )
    EngagementStore(db).transition(engagement.id, "scope_review", "operator")
    EngagementStore(db).transition(engagement.id, "active", "operator")
    artifact = ingest_evidence(
        db, engagements_root=tmp_path / "engagements",
        engagement_id=engagement.id, source_name="fixture.json",
        content_type="application/json", content=b'{"observation":"safe"}',
        actor="operator",
    )
    monkeypatch.setattr(
        client_mod, "_ollama_chat",
        lambda **kwargs: SimpleNamespace(
            message=SimpleNamespace(content=_model_response(artifact.evidence_id)),
        ),
    )
    triage = triage_artifact(
        db=db, engagement_id=engagement.id, artifact_id=artifact.evidence_id,
    )
    yield db, engagement.id, triage.finding_id
    client_mod._reset_circuit_for_tests()
    db.close()


def test_human_transition_requires_evidence_and_audits_atomically(finding_env):
    db, engagement_id, finding_id = finding_env
    store = FindingStore(db)

    row = store.transition(finding_id, "ready_for_review", actor="operator")
    assert row["lifecycle_state"] == "ready_for_review"
    audit = db.connection.execute(
        "SELECT event_type, decision, details_json FROM audit_events "
        "WHERE engagement_id = ? ORDER BY seq DESC LIMIT 1", (engagement_id,),
    ).fetchone()
    assert audit["event_type"] == "finding_transition"
    assert audit["decision"] == "ready_for_review"
    assert json.loads(audit["details_json"])["finding_id"] == finding_id


def test_model_cannot_skip_review_state(finding_env):
    _db, _engagement_id, finding_id = finding_env
    with pytest.raises(FindingError, match="cannot transition"):
        FindingStore(_db).transition(
            finding_id, "human_validated", actor="operator",
        )


def test_empty_actor_cannot_promote_finding(finding_env):
    db, _engagement_id, finding_id = finding_env
    with pytest.raises(FindingError, match="actor is required"):
        FindingStore(db).transition(
            finding_id, "ready_for_review", actor=" ",
        )


def test_audit_failure_rolls_back_state_change(finding_env, monkeypatch):
    db, _engagement_id, finding_id = finding_env

    def fail_append(*args, **kwargs):
        raise RuntimeError("audit storage unavailable")

    monkeypatch.setattr("sentinel.findings.store.AuditStore.append", fail_append)
    with pytest.raises(RuntimeError, match="audit storage unavailable"):
        FindingStore(db).transition(
            finding_id, "ready_for_review", actor="operator",
        )
    assert FindingStore(db).get(finding_id)["lifecycle_state"] == "candidate"


def test_ready_for_review_requires_non_held_evidence(finding_env):
    db, _engagement_id, finding_id = finding_env
    evidence_id = db.connection.execute(
        "SELECT artifact_id FROM finding_evidence WHERE finding_id = ?",
        (finding_id,),
    ).fetchone()[0]
    db.connection.execute(
        "UPDATE artifacts SET redaction_status='held_for_review' WHERE id = ?",
        (evidence_id,),
    )
    with pytest.raises(FindingError, match="requires safe"):
        FindingStore(db).transition(
            finding_id, "ready_for_review", actor="operator",
        )


def test_human_validation_requires_review_ready_state(finding_env):
    db, _engagement_id, finding_id = finding_env
    store = FindingStore(db)
    store.transition(finding_id, "ready_for_review", actor="operator")
    validated = store.transition(finding_id, "human_validated", actor="operator")
    assert validated["lifecycle_state"] == "human_validated"
    report_ready = store.transition(finding_id, "report_ready", actor="operator")
    assert report_ready["lifecycle_state"] == "report_ready"

