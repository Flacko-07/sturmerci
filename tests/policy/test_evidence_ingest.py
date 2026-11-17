# SPDX-License-Identifier: Apache-2.0
"""Evidence ingestion pipeline: happy path, rejections, redaction, cross-engagement."""
import pytest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sentinel.storage.db import Database
from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence, EvidenceRejected
from sentinel.evidence.store import (
    EvidenceStore, EvidenceCrossEngagement, release_held_artifact,
)
from sentinel.audit.store import AuditStore


@pytest.fixture
def active_eng(tmp_path):
    db = Database(tmp_path / "x.db")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab", program_name="lab", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")
    return db, eng.id, tmp_path / "engagements"


def test_happy_path(active_eng):
    db, eng_id, root = active_eng
    r = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_id,
        source_name="notes.txt", content_type="text/plain",
        content=b"hello world", actor="op",
    )
    assert r.redaction_status == "clean"
    assert r.evidence_id.startswith("ev_")
    art = EvidenceStore(db).get(r.evidence_id)
    assert art is not None
    assert art.engagement_id == eng_id
    db.close()


def test_execution_capture_metadata_roundtrips(active_eng):
    db, eng_id, root = active_eng
    r = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_id,
        source_name="partial.txt", content_type="text/plain",
        content=b"partial scanner output", actor="op",
        truncated_output=True, execution_status="PARTIAL",
        stdout_bytes=22, stderr_bytes=7, output_limit_bytes=29,
        stdout_truncated=True, stderr_truncated=False,
        timed_out=False, terminated=False, process_exit_code=0,
    )
    artifact = EvidenceStore(db).get(r.evidence_id)
    assert artifact.execution_status == "PARTIAL"
    assert artifact.stdout_bytes == 22
    assert artifact.stderr_bytes == 7
    assert artifact.output_limit_bytes == 29
    assert artifact.stdout_truncated is True
    assert artifact.stderr_truncated is False
    assert artifact.timed_out is False
    assert artifact.terminated is False
    assert artifact.process_exit_code == 0
    db.close()


def test_redaction_applied(active_eng):
    db, eng_id, root = active_eng
    payload = b"AWS=AKIAIOSFODNN7EXAMPLE"
    r = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_id,
        source_name="leaked.env", content_type="text/plain",
        content=payload, actor="op",
    )
    assert r.redaction_status == "redacted"
    # Verify the on-disk sanitized file has no key
    art = EvidenceStore(db).get(r.evidence_id)
    from pathlib import Path
    sanitized = Path(art.sanitized_path).read_text()
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "[REDACTED:aws_access_key]" in sanitized
    db.close()


def test_unknown_format_held_for_review(active_eng):
    db, eng_id, root = active_eng
    payload = b"secret=" + b"Z" * 60
    r = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_id,
        source_name="unknown.txt", content_type="text/plain",
        content=payload, actor="op",
    )
    assert r.redaction_status == "held_for_review"
    assert r.unknown_format_triggered is True
    db.close()


def test_oversize_rejected(active_eng):
    db, eng_id, root = active_eng
    with pytest.raises(EvidenceRejected, match="too large"):
        ingest_evidence(
            db, engagements_root=root, engagement_id=eng_id,
            source_name="big", content_type="text/plain",
            content=b"a" * (26 * 1024 * 1024), actor="op",
        )
    db.close()


def test_wrong_content_type_rejected(active_eng):
    db, eng_id, root = active_eng
    with pytest.raises(EvidenceRejected, match="not allowed"):
        ingest_evidence(
            db, engagements_root=root, engagement_id=eng_id,
            source_name="x.bin", content_type="application/octet-stream",
            content=b"\x00\x01", actor="op",
        )
    db.close()


def test_binary_content_rejected(active_eng):
    db, eng_id, root = active_eng
    with pytest.raises(EvidenceRejected, match="UTF-8"):
        ingest_evidence(
            db, engagements_root=root, engagement_id=eng_id,
            source_name="x.txt", content_type="text/plain",
            content=b"\xff\xfe\x00", actor="op",
        )
    db.close()


def test_inactive_engagement_rejects(active_eng, tmp_path):
    db, _, root = active_eng
    store = EngagementStore(db)
    eng = store.create(
        platform="lab", program_name="lab2", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    with pytest.raises(EvidenceRejected, match="'active'"):
        ingest_evidence(
            db, engagements_root=root, engagement_id=eng.id,
            source_name="x", content_type="text/plain",
            content=b"hello", actor="op",
        )
    db.close()


def test_cross_engagement_access_denied(active_eng, tmp_path):
    db, eng_a, root = active_eng
    store = EngagementStore(db)
    eng_b = store.create(
        platform="lab", program_name="lab_b", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    store.transition(eng_b.id, "scope_review", "op")
    store.transition(eng_b.id, "active", "op")

    r = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_a,
        source_name="x", content_type="text/plain",
        content=b"hello", actor="op",
    )
    with pytest.raises(EvidenceCrossEngagement):
        EvidenceStore(db).assert_in_engagement(r.evidence_id, eng_b.id)
    db.close()


def test_audit_event_written(active_eng):
    db, eng_id, root = active_eng
    r = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_id,
        source_name="x", content_type="text/plain",
        content=b"hello", actor="op",
    )
    row = db.connection.execute(
        "SELECT * FROM audit_events WHERE event_type = 'evidence_ingested'"
    ).fetchone()
    assert row is not None
    assert r.evidence_id in row["details_json"]
    db.close()


def test_held_evidence_release_rolls_back_if_audit_fails(active_eng, monkeypatch):
    db, eng_id, root = active_eng
    artifact = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_id,
        source_name="unknown.txt", content_type="text/plain",
        content=b"secret=" + b"Z" * 60, actor="op",
    )
    assert artifact.redaction_status == "held_for_review"

    def fail_audit(*args, **kwargs):
        raise RuntimeError("audit storage unavailable")

    monkeypatch.setattr(AuditStore, "append", fail_audit)
    with pytest.raises(RuntimeError, match="audit storage unavailable"):
        release_held_artifact(
            db, artifact.evidence_id, engagement_id=eng_id, reviewer="reviewer",
        )
    current = EvidenceStore(db).get(artifact.evidence_id)
    assert current.redaction_status == "held_for_review"
    db.close()


def test_held_evidence_release_is_audited_and_idempotently_refused(active_eng):
    db, eng_id, root = active_eng
    artifact = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_id,
        source_name="unknown.txt", content_type="text/plain",
        content=b"secret=" + b"Z" * 60, actor="op",
    )
    release_held_artifact(
        db, artifact.evidence_id, engagement_id=eng_id, reviewer="reviewer",
    )
    assert EvidenceStore(db).get(artifact.evidence_id).redaction_status == "redacted"
    assert db.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type='evidence_released'"
    ).fetchone()[0] == 1
    with pytest.raises(ValueError, match="not held_for_review|no longer"):
        release_held_artifact(
            db, artifact.evidence_id, engagement_id=eng_id, reviewer="reviewer",
        )
    assert db.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type='evidence_released'"
    ).fetchone()[0] == 1
    db.close()


def test_held_evidence_release_requires_actor_label(active_eng):
    db, eng_id, root = active_eng
    artifact = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_id,
        source_name="unknown.txt", content_type="text/plain",
        content=b"secret=" + b"Z" * 60, actor="op",
    )
    with pytest.raises(ValueError, match="reviewer is required"):
        release_held_artifact(
            db, artifact.evidence_id, engagement_id=eng_id, reviewer=" ",
        )
    assert EvidenceStore(db).get(artifact.evidence_id).redaction_status == "held_for_review"
    db.close()


def test_concurrent_held_evidence_release_commits_once(active_eng):
    db, eng_id, root = active_eng
    artifact = ingest_evidence(
        db, engagements_root=root, engagement_id=eng_id,
        source_name="unknown.txt", content_type="text/plain",
        content=b"secret=" + b"Z" * 60, actor="op",
    )
    barrier = Barrier(2)

    def attempt_release():
        worker_db = Database(db.path)
        try:
            barrier.wait()
            release_held_artifact(
                worker_db, artifact.evidence_id,
                engagement_id=eng_id, reviewer="reviewer",
            )
            return "released"
        except ValueError:
            return "refused"
        finally:
            worker_db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _idx: attempt_release(), range(2)))
    assert outcomes.count("released") == 1
    assert outcomes.count("refused") == 1
    assert db.connection.execute(
        "SELECT redaction_status FROM artifacts WHERE id=?",
        (artifact.evidence_id,),
    ).fetchone()[0] == "redacted"
    assert db.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type='evidence_released'"
    ).fetchone()[0] == 1
    db.close()
