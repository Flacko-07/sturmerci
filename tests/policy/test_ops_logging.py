# SPDX-License-Identifier: Apache-2.0
"""Operational log isolation and redaction."""

import pytest

from sentinel.storage.db import Database
from sentinel.engagement.store import EngagementStore
from sentinel.logging.ops import OpsLogger


@pytest.fixture
def db_with_eng(tmp_path):
    db = Database(tmp_path / "x.db")
    eng = EngagementStore(db).create(
        platform="lab",
        program_name="lab",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    return db, eng.id


def test_message_written_and_redacted(db_with_eng):
    db, eng_id = db_with_eng
    logger = OpsLogger(db)
    logger.log(
        engagement_id=eng_id,
        level="info",
        component="ingest",
        message="Scanning with AKIAIOSFODNN7EXAMPLE leaked",
        details={"note": "secret=AKIAIOSFODNN7EXAMPLE"},
    )
    row = db.connection.execute(
        "SELECT message, details_json FROM operational_logs"
    ).fetchone()
    assert "AKIAIOSFODNN7EXAMPLE" not in row["message"]
    assert "AKIAIOSFODNN7EXAMPLE" not in row["details_json"]
    assert "[REDACTED:aws_access_key]" in row["message"]
    db.close()


def test_invalid_level_rejected(db_with_eng):
    db, eng_id = db_with_eng
    with pytest.raises(ValueError):
        OpsLogger(db).log(
            engagement_id=eng_id,
            level="verbose",
            component="x",
            message="y",
        )
    db.close()


def test_ops_does_not_pollute_audit(db_with_eng):
    db, eng_id = db_with_eng
    audit_before = db.connection.execute(
        "SELECT COUNT(*) FROM audit_events"
    ).fetchone()[0]
    OpsLogger(db).log(
        engagement_id=eng_id,
        level="info",
        component="x",
        message="y",
    )
    audit_after = db.connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[
        0
    ]
    assert audit_before == audit_after  # ops log does not create audit events
    db.close()
