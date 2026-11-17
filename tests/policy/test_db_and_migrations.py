# SPDX-License-Identifier: Apache-2.0
"""Consolidated DB, migration idempotency, foreign keys, engagement isolation."""

import pytest

from sentinel.storage.db import Database
from sentinel.storage.migrate import migrate


def test_migrations_apply_once(tmp_path):
    db = Database(tmp_path / "x.db")
    applied = migrate(db)
    assert applied == []  # auto-migrated in __init__
    assert migrate(db) == []
    artifact_columns = {
        row["name"]
        for row in db.connection.execute("PRAGMA table_info(artifacts)").fetchall()
    }
    assert {
        "execution_status",
        "stdout_bytes",
        "stderr_bytes",
        "output_limit_bytes",
        "stdout_truncated",
        "stderr_truncated",
        "timed_out",
        "terminated",
        "process_exit_code",
    } <= artifact_columns
    db.close()


def test_foreign_keys_enforced(tmp_path):
    db = Database(tmp_path / "x.db")
    with pytest.raises(Exception):
        db.connection.execute(
            "INSERT INTO artifacts (id, engagement_id, source_name, content_type, "
            "raw_sha256, sanitized_sha256, raw_size_bytes, sanitized_size_bytes, "
            "raw_path, sanitized_path, redaction_status, unknown_format_triggered, "
            "actor, created_at_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "ev_x",
                "eng_does_not_exist",
                "s",
                "text/plain",
                "h",
                "h",
                0,
                0,
                "/x",
                "/y",
                "clean",
                0,
                "op",
                "now",
            ),
        )
    db.close()


def test_transaction_rolls_back(tmp_path):
    db = Database(tmp_path / "x.db")
    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO engagements (id, platform, program_name, policy_url, "
                "state, created_at_utc, updated_at_utc, created_by) "
                "VALUES ('eng_a','h1','p','u','draft','t','t','op')"
            )
            raise RuntimeError("boom")
    assert db.connection.execute("SELECT COUNT(*) FROM engagements").fetchone()[0] == 0
    db.close()


def test_engagement_state_check_constraint(tmp_path):
    db = Database(tmp_path / "x.db")
    with pytest.raises(Exception):
        db.connection.execute(
            "INSERT INTO engagements (id, platform, program_name, policy_url, "
            "state, created_at_utc, updated_at_utc, created_by) "
            "VALUES ('eng_b','h1','p','u','not_a_state','t','t','op')"
        )
    db.close()
