# SPDX-License-Identifier: Apache-2.0
"""Triage pipeline tests. LLM mocked, DB and KB real."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence
from sentinel.knowledge.ingest import ingest_file
from sentinel.knowledge.provenance import review_revision
from sentinel.llm import client as client_mod
from sentinel.storage.db import Database
from sentinel.triage.pipeline import triage_artifact, TriageError
from sentinel.triage.query_builder import build_kb_query


KB_DOC = """---
title: Sensitive Data Exposure
topic: web_security
source_url: https://test/sensitive
publisher: Test
version: "1.0"
license: CC-BY-SA-4.0
review_status: reviewed
---
Sensitive data exposure includes leaked credentials, tokens, and
API keys in source code or shipped artifacts. Testing involves
searching for known secret patterns and confirming liveness.
References: CWE-200.
"""


def _fake_response(content: str):
    return SimpleNamespace(message=SimpleNamespace(content=content))


def _triage_json(artifact_id: str, **overrides) -> str:
    payload = {
        "task_type": "finding_triage",
        "summary": "Potential credential exposure in artifact",
        "candidate_category": "information_exposure",
        "possible_references": ["CWE-200"],
        "evidence_ids": [artifact_id],
        "missing_evidence": ["Confirm the credential is live"],
        "confidence_hint": "medium",
        "recommended_next_step": "Human review of the leaked credential",
    }
    payload.update(overrides)
    return json.dumps(payload)


@pytest.fixture
def env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="triage-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    artifact = ingest_evidence(
        db,
        engagements_root=tmp_path / "engagements",
        engagement_id=eng.id,
        source_name="gitleaks_8.30.1.json",
        content_type="application/json",
        content=b'{"RuleID":"aws-access-token","File":"config.py"}',
        actor="op",
    )

    kb_dir = tmp_path / "kb"
    kb_dir.mkdir()
    (kb_dir / "sensitive.md").write_text(KB_DOC)
    entry_id = ingest_file(db, kb_dir / "sensitive.md", ingested_by="curator")
    review_revision(
        db,
        entry_id,
        reviewer="reviewer",
        decision="approved",
        rationale="fixture source checked",
    )

    yield {
        "db": db,
        "eng_id": eng.id,
        "artifact_id": artifact.evidence_id,
        "tmp_path": tmp_path,
    }
    db.close()


def _mock_llm(monkeypatch, json_response: str):
    monkeypatch.setattr(
        client_mod,
        "_ollama_chat",
        lambda **kw: _fake_response(json_response),
    )


# --- happy path ---


def test_happy_path_creates_finding(env, monkeypatch):
    _mock_llm(monkeypatch, _triage_json(env["artifact_id"]))

    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )

    assert result.finding_id.startswith("find_")
    assert result.dropped_evidence == 0
    assert result.dropped_references == 0
    assert result.model_run_id

    finding = (
        env["db"]
        .connection.execute(
            "SELECT * FROM findings WHERE id = ?",
            (result.finding_id,),
        )
        .fetchone()
    )
    assert finding is not None
    assert finding["lifecycle_state"] == "candidate"
    assert finding["candidate_category"] == "information_exposure"
    assert finding["confidence_hint"] == "medium"
    assert finding["artifact_id"] == env["artifact_id"]

    evidence_rows = (
        env["db"]
        .connection.execute(
            "SELECT evidence_id FROM finding_evidence WHERE finding_id = ?",
            (result.finding_id,),
        )
        .fetchall()
    )
    assert len(evidence_rows) == 1
    assert evidence_rows[0]["evidence_id"] == env["artifact_id"]

    audit = (
        env["db"]
        .connection.execute(
            "SELECT * FROM audit_events WHERE event_type = 'triage_completed'"
        )
        .fetchone()
    )
    assert audit is not None
    assert result.finding_id in audit["details_json"]


def test_happy_path_uses_kb_hits(env, monkeypatch):
    """Filename gitleaks -> KB query -> sensitive doc found."""
    _mock_llm(monkeypatch, _triage_json(env["artifact_id"]))

    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    assert len(result.kb_hits) >= 1
    assert "Sensitive" in result.kb_hits[0].title


# --- error paths ---


def test_missing_artifact(env):
    with pytest.raises(TriageError, match="not found"):
        triage_artifact(
            db=env["db"],
            engagement_id=env["eng_id"],
            artifact_id="ev_does_not_exist",
        )


def test_wrong_engagement(env, monkeypatch):
    _mock_llm(monkeypatch, _triage_json(env["artifact_id"]))
    with pytest.raises(TriageError, match="belongs to"):
        triage_artifact(
            db=env["db"],
            engagement_id="eng_other",
            artifact_id=env["artifact_id"],
        )


def test_modified_evidence_is_rejected_before_model_call(env, monkeypatch):
    path = (
        env["db"]
        .connection.execute(
            "SELECT sanitized_path FROM artifacts WHERE id=?",
            (env["artifact_id"],),
        )
        .fetchone()[0]
    )
    from pathlib import Path

    Path(path).write_text("altered after ingest")
    called = {"value": False}

    def _must_not_call(**kwargs):
        called["value"] = True
        raise AssertionError("LLM must not receive modified evidence")

    monkeypatch.setattr(client_mod, "_ollama_chat", _must_not_call)
    with pytest.raises(TriageError, match="integrity mismatch"):
        triage_artifact(
            db=env["db"],
            engagement_id=env["eng_id"],
            artifact_id=env["artifact_id"],
        )
    assert called["value"] is False
    assert (
        env["db"]
        .connection.execute(
            "SELECT COUNT(*) FROM audit_events WHERE event_type='evidence_integrity_rejected'"
        )
        .fetchone()[0]
        == 1
    )


def test_missing_evidence_is_rejected_before_model_call(env, monkeypatch):
    path = (
        env["db"]
        .connection.execute(
            "SELECT sanitized_path FROM artifacts WHERE id=?",
            (env["artifact_id"],),
        )
        .fetchone()[0]
    )
    from pathlib import Path

    Path(path).unlink()
    called = {"value": False}

    def _must_not_call(**kwargs):
        called["value"] = True
        raise AssertionError("LLM must not receive missing evidence")

    monkeypatch.setattr(client_mod, "_ollama_chat", _must_not_call)
    with pytest.raises(TriageError, match="integrity mismatch|cannot read"):
        triage_artifact(
            db=env["db"],
            engagement_id=env["eng_id"],
            artifact_id=env["artifact_id"],
        )
    assert called["value"] is False


def test_incomplete_execution_cannot_be_triaged(env, monkeypatch):
    called = {"value": False}

    def _must_not_call(**kwargs):
        called["value"] = True
        raise AssertionError("LLM must not receive incomplete scan output")

    monkeypatch.setattr(client_mod, "_ollama_chat", _must_not_call)
    env["db"].connection.execute(
        "UPDATE artifacts SET execution_status='TIMED_OUT' WHERE id=?",
        (env["artifact_id"],),
    )
    with pytest.raises(TriageError, match="execution status 'TIMED_OUT'"):
        triage_artifact(
            db=env["db"],
            engagement_id=env["eng_id"],
            artifact_id=env["artifact_id"],
        )
    assert called["value"] is False


# --- evidence validation ---


def test_fabricated_evidence_id_dropped(env, monkeypatch):
    """Model emits this artifact_id + a fake one. Fake is dropped; finding kept."""
    fake = "ev_" + "f" * 16
    _mock_llm(
        monkeypatch,
        _triage_json(
            env["artifact_id"],
            evidence_ids=[env["artifact_id"], fake],
        ),
    )
    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    assert result.dropped_evidence == 1
    ev_rows = (
        env["db"]
        .connection.execute(
            "SELECT evidence_id FROM finding_evidence WHERE finding_id = ?",
            (result.finding_id,),
        )
        .fetchall()
    )
    assert len(ev_rows) == 1
    assert ev_rows[0]["evidence_id"] == env["artifact_id"]


def test_all_evidence_fabricated_fails(env, monkeypatch):
    """Model emits only fake evidence. No finding written; TriageError."""
    fake = "ev_" + "a" * 16
    _mock_llm(
        monkeypatch,
        _triage_json(
            env["artifact_id"],
            evidence_ids=[fake],
        ),
    )
    with pytest.raises(TriageError, match="no valid evidence"):
        triage_artifact(
            db=env["db"],
            engagement_id=env["eng_id"],
            artifact_id=env["artifact_id"],
        )
    count = env["db"].connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert count == 0


# --- reference validation ---


def test_fabricated_cwe_dropped(env, monkeypatch):
    """Model references CWE-99999 (structurally valid, not in KB). Dropped."""
    _mock_llm(
        monkeypatch,
        _triage_json(
            env["artifact_id"],
            possible_references=["CWE-99999"],
        ),
    )
    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    assert result.dropped_references == 1
    finding = (
        env["db"]
        .connection.execute(
            "SELECT possible_references_json FROM findings WHERE id = ?",
            (result.finding_id,),
        )
        .fetchone()
    )
    assert json.loads(finding["possible_references_json"]) == []


def test_known_cwe_kept(env, monkeypatch):
    _mock_llm(
        monkeypatch,
        _triage_json(
            env["artifact_id"],
            possible_references=["CWE-200", "CWE-99999"],
        ),
    )
    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    assert result.dropped_references == 1  # only 99999 dropped
    finding = (
        env["db"]
        .connection.execute(
            "SELECT possible_references_json FROM findings WHERE id = ?",
            (result.finding_id,),
        )
        .fetchone()
    )
    kept = json.loads(finding["possible_references_json"])
    assert kept == ["CWE-200"]


def test_triage_persists_all_reference_validation_provenance(env, monkeypatch):
    _mock_llm(
        monkeypatch,
        _triage_json(
            env["artifact_id"],
            possible_references=["CVE-2025-12345", "CWE-200", "CWE-99999"],
        ),
    )
    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    rows = (
        env["db"]
        .connection.execute(
            "SELECT original_identifier, validation_status, validation_source, "
            "lookup_outcome, rejection_reason FROM finding_reference_provenance "
            "WHERE finding_id=? ORDER BY original_identifier",
            (result.finding_id,),
        )
        .fetchall()
    )
    states = {row["original_identifier"]: row["validation_status"] for row in rows}
    assert states == {
        "CVE-2025-12345": "unverified",
        "CWE-200": "verified",
        "CWE-99999": "invalid",
    }
    assert (
        next(r for r in rows if r["original_identifier"] == "CVE-2025-12345")[
            "lookup_outcome"
        ]
        == "cache_miss"
    )
    assert (
        next(r for r in rows if r["original_identifier"] == "CWE-99999")[
            "rejection_reason"
        ]
        == "malformed_or_unknown_reference"
    )


# --- KB degraded mode ---


def test_no_kb_hits_still_works(env, monkeypatch):
    """An empty KB search still produces a finding without mutating history."""
    import sentinel.triage.pipeline as triage_pipeline

    monkeypatch.setattr(triage_pipeline, "search", lambda *args, **kwargs: [])

    _mock_llm(monkeypatch, _triage_json(env["artifact_id"]))
    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    assert result.kb_hits == []
    assert result.finding_id.startswith("find_")


# --- query builder unit tests ---


def test_query_builder_cve_priority():
    q = build_kb_query(
        source_name="scan.json",
        content_type="application/json",
        content="Found CVE-2024-12345 in dependency",
    )
    assert q == "CVE-2024-12345"


def test_query_builder_filename_hint():
    q = build_kb_query(
        source_name="gitleaks_8.30.1.json",
        content_type="application/json",
        content="no identifiers here",
    )
    assert "sensitive data exposure" in q


def test_query_builder_sqli_hint():
    q = build_kb_query(
        source_name="sqli-results.txt",
        content_type="text/plain",
        content="nothing CVE or CWE",
    )
    assert q == "SQL injection"


def test_query_builder_content_fallback():
    q = build_kb_query(
        source_name="unknown.log",
        content_type="text/plain",
        content="kubernetes helm chart values exposed",
    )
    assert "kubernetes" in q.lower() or "helm" in q.lower()


# --- M8-P0-A: held_for_review refuses triage ---


def test_held_for_review_artifact_refused(tmp_path):
    """Artifact with held_for_review status must not reach the LLM."""
    from sentinel.engagement.store import EngagementStore
    from sentinel.evidence.ingest import ingest_evidence

    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="held-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    # 60-char unknown-format token -> unknown_format_triggered -> held_for_review
    result = ingest_evidence(
        db,
        engagements_root=tmp_path / "engagements",
        engagement_id=eng.id,
        source_name="unknown.txt",
        content_type="text/plain",
        content=b"x=" + b"Z" * 60,
        actor="op",
    )
    assert result.redaction_status == "held_for_review"

    try:
        with pytest.raises(TriageError, match="held for review"):
            triage_artifact(
                db=db,
                engagement_id=eng.id,
                artifact_id=result.evidence_id,
            )
    finally:
        db.close()


# --- M8-3: dropped_references recorded in model_runs ---


def test_m8p03_dropped_references_recorded_in_model_runs(env, monkeypatch):
    """After triage, model_runs.dropped_references reflects the true count."""
    _mock_llm(
        monkeypatch,
        _triage_json(
            env["artifact_id"],
            possible_references=["CWE-200", "CWE-99999", "CWE-88888"],
        ),
    )
    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    assert result.dropped_references == 2
    row = (
        env["db"]
        .connection.execute(
            "SELECT dropped_references FROM model_runs WHERE run_id = ?",
            (result.model_run_id,),
        )
        .fetchone()
    )
    assert row is not None
    assert row["dropped_references"] == 2


# --- M8-4: finding + audit are atomic ---


def test_m8p04_audit_failure_rolls_back_finding(env, monkeypatch):
    """If the audit append fails inside triage, no finding is written."""
    _mock_llm(monkeypatch, _triage_json(env["artifact_id"]))

    # Make AuditStore.append raise after the finding INSERT has run
    from sentinel.audit.store import AuditStore

    def _boom(self, *args, **kwargs):
        raise RuntimeError("simulated audit failure")

    monkeypatch.setattr(AuditStore, "append", _boom)

    with pytest.raises(RuntimeError, match="simulated audit failure"):
        triage_artifact(
            db=env["db"],
            engagement_id=env["eng_id"],
            artifact_id=env["artifact_id"],
        )

    # No finding should have committed
    n = env["db"].connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert n == 0, f"finding leaked despite audit failure: {n}"


# --- M8.4b: pipeline integration with use_fewshot ---


def test_m8p4b_pipeline_uses_v2_when_fewshot_requested(env, monkeypatch):
    """use_fewshot=True -> V2 prompt hash recorded."""
    _mock_llm(monkeypatch, _triage_json(env["artifact_id"]))
    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
        use_fewshot=True,
    )
    from sentinel.llm.prompts import TRIAGE_V2

    row = (
        env["db"]
        .connection.execute(
            "SELECT prompt_template_hash FROM model_runs WHERE run_id = ?",
            (result.model_run_id,),
        )
        .fetchone()
    )
    assert row["prompt_template_hash"] == TRIAGE_V2.hash


def test_m8p4b_pipeline_uses_v1_by_default(env, monkeypatch):
    """use_fewshot=False (default) -> V1 prompt hash, examples_used empty."""
    _mock_llm(monkeypatch, _triage_json(env["artifact_id"]))
    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    from sentinel.llm.prompts import TRIAGE_V1

    row = (
        env["db"]
        .connection.execute(
            "SELECT prompt_template_hash FROM model_runs WHERE run_id = ?",
            (result.model_run_id,),
        )
        .fetchone()
    )
    assert row["prompt_template_hash"] == TRIAGE_V1.hash
    assert result.examples_used == ()


def test_m8p4b_pipeline_records_examples_used(env, monkeypatch):
    """When few-shot retrieves matches, they're in result.examples_used."""
    import uuid
    from datetime import datetime, timezone

    # Insert a validated finding that will match the gitleaks artifact
    fid = "find_" + uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc).isoformat()
    with env["db"].transaction() as conn:
        conn.execute(
            """INSERT INTO findings
               (id, engagement_id, asset_id, artifact_id, title,
                candidate_category, confidence_hint, lifecycle_state,
                summary, recommended_next_step, missing_evidence_json,
                possible_references_json, kb_hits_json, model_run_id,
                created_at_utc, created_by)
               VALUES (?, ?, NULL, ?, 'prior', 'information_exposure',
                       'high', 'human_validated',
                       'AWS access token leaked in config', 'Rotate',
                       '[]', ?, '[]', NULL, ?, 'op')""",
            (fid, env["eng_id"], env["artifact_id"], json.dumps(["CWE-798"]), now),
        )
    # The gitleaks fixture content includes "aws-access-token" -- should match
    _mock_llm(monkeypatch, _triage_json(env["artifact_id"]))
    result = triage_artifact(
        db=env["db"],
        engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
        use_fewshot=True,
    )
    # At least the prior finding should be retrieved
    assert fid in result.examples_used
