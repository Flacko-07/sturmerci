# SPDX-License-Identifier: Apache-2.0
"""Few-shot retrieval tests (M8.4b)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.approval.store import target_asset_ids_hash
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence
from sentinel.llm.fewshot import (
    retrieve_similar_examples, FewShotExample, MAX_K, MIN_SCORE,
)
from sentinel.storage.db import Database


def _make_validated_finding(
    db, eng_id, *, artifact_id, summary, refs, state="human_validated",
):
    """Insert a synthetic validated finding for testing retrieval."""
    import uuid
    fid = "find_" + uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc).isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO findings
               (id, engagement_id, asset_id, artifact_id, title,
                candidate_category, confidence_hint, lifecycle_state,
                summary, recommended_next_step, missing_evidence_json,
                possible_references_json, kb_hits_json, model_run_id,
                created_at_utc, created_by)
               VALUES (?, ?, NULL, ?, ?, 'injection', 'medium', ?,
                       ?, 'Verify manually', '[]', ?, '[]', NULL, ?, 'op')""",
            (fid, eng_id, artifact_id, summary[:200], state,
             summary, json.dumps(refs), now),
        )
    return fid


@pytest.fixture
def env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab", program_name="fewshot-test", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    # Create 3 artifacts (each will back one validated finding)
    artifact_ids = []
    for i, content in enumerate([
        b"SQL injection in login parameter id=1 OR 1=1--",
        b"XSS reflected in search q=<script>alert(1)</script>",
        b"SSRF via image_url parameter fetching internal URL",
    ]):
        r = ingest_evidence(
            db, engagements_root=tmp_path / "engagements",
            engagement_id=eng.id,
            source_name=f"ev{i}.txt", content_type="text/plain",
            content=content, actor="op",
        )
        artifact_ids.append(r.evidence_id)

    yield {
        "db": db, "eng_id": eng.id, "artifacts": artifact_ids,
        "tmp_path": tmp_path,
    }
    db.close()


# --- Retrieval ---

def test_empty_engagement_returns_no_examples(env):
    result = retrieve_similar_examples(
        env["db"], engagement_id=env["eng_id"],
        evidence_text="SQL injection evidence",
    )
    assert result == []


def test_retrieval_finds_matching_validated_finding(env):
    _make_validated_finding(
        env["db"], env["eng_id"],
        artifact_id=env["artifacts"][0],
        summary="SQL injection vulnerability in login endpoint",
        refs=["CWE-89"],
    )
    # Query about SQL should match
    result = retrieve_similar_examples(
        env["db"], engagement_id=env["eng_id"],
        evidence_text="parameter id contains SQL injection payload",
    )
    assert len(result) == 1
    assert "SQL" in result[0].output_json
    assert result[0].score >= MIN_SCORE


def test_retrieval_ranks_correct_example_first(env):
    _make_validated_finding(
        env["db"], env["eng_id"], artifact_id=env["artifacts"][0],
        summary="SQL injection in login", refs=["CWE-89"],
    )
    _make_validated_finding(
        env["db"], env["eng_id"], artifact_id=env["artifacts"][1],
        summary="Reflected XSS in search", refs=["CWE-79"],
    )
    result = retrieve_similar_examples(
        env["db"], engagement_id=env["eng_id"],
        evidence_text="SQL injection quote bypass payload",
    )
    assert len(result) >= 1
    assert "SQL" in result[0].output_json
    assert result[0].score >= result[-1].score


def test_retrieval_excludes_non_validated_states(env):
    """Only human_validated / report_ready / resolved count."""
    _make_validated_finding(
        env["db"], env["eng_id"], artifact_id=env["artifacts"][0],
        summary="SQL injection in login", refs=["CWE-89"],
        state="candidate",  # NOT validated
    )
    result = retrieve_similar_examples(
        env["db"], engagement_id=env["eng_id"],
        evidence_text="SQL injection evidence",
    )
    assert result == []


def test_retrieval_excludes_rejected(env):
    _make_validated_finding(
        env["db"], env["eng_id"], artifact_id=env["artifacts"][0],
        summary="SQL injection in login", refs=["CWE-89"],
        state="rejected",
    )
    result = retrieve_similar_examples(
        env["db"], engagement_id=env["eng_id"],
        evidence_text="SQL injection evidence",
    )
    assert result == []


def test_retrieval_cross_engagement_isolation(env, tmp_path):
    """A validated finding from a DIFFERENT engagement must NOT appear."""
    _make_validated_finding(
        env["db"], env["eng_id"], artifact_id=env["artifacts"][0],
        summary="SQL injection in login", refs=["CWE-89"],
    )
    # Create another engagement and query against it
    other = EngagementStore(env["db"]).create(
        platform="lab", program_name="other", policy_url=None,
        actor="op", engagements_root=env["tmp_path"] / "eng2",
    )
    result = retrieve_similar_examples(
        env["db"], engagement_id=other.id,
        evidence_text="SQL injection evidence",
    )
    assert result == []


def test_retrieval_respects_k_limit(env):
    for i in range(4):
        _make_validated_finding(
            env["db"], env["eng_id"],
            artifact_id=env["artifacts"][i % 3],
            summary=f"SQL injection variation {i}", refs=["CWE-89"],
        )
    result = retrieve_similar_examples(
        env["db"], engagement_id=env["eng_id"],
        evidence_text="SQL injection in parameter",
        k=2,
    )
    assert len(result) <= 2


def test_retrieval_k_capped_at_max(env):
    for i in range(5):
        _make_validated_finding(
            env["db"], env["eng_id"],
            artifact_id=env["artifacts"][i % 3],
            summary=f"SQL injection variation {i}", refs=["CWE-89"],
        )
    result = retrieve_similar_examples(
        env["db"], engagement_id=env["eng_id"],
        evidence_text="SQL injection in parameter",
        k=100,  # way over MAX_K
    )
    assert len(result) <= MAX_K


def test_retrieval_evidence_snippet_from_sanitized_file(env):
    _make_validated_finding(
        env["db"], env["eng_id"], artifact_id=env["artifacts"][0],
        summary="SQL injection in login", refs=["CWE-89"],
    )
    result = retrieve_similar_examples(
        env["db"], engagement_id=env["eng_id"],
        evidence_text="SQL injection",
    )
    assert len(result) == 1
    # Snippet comes from sanitized artifact, contains the original content
    assert "SQL" in result[0].evidence_snippet
