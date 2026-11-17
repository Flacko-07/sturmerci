# SPDX-License-Identifier: Apache-2.0
"""Knowledge CLI exposes current immutable revisions for review."""

from __future__ import annotations

from typer.testing import CliRunner

import sentinel.cli as cli_module
from sentinel.cli import app
from sentinel.knowledge.ingest import ingest_file
from sentinel.storage.db import Database


def test_knowledge_list_shows_entry_and_unreviewed_state(tmp_path, monkeypatch):
    db = Database(tmp_path / "sentinel.sqlite3")
    source = tmp_path / "knowledge.md"
    source.write_text(
        "---\n"
        "title: Review me\n"
        "topic: test\n"
        "source_url: https://example.test/kb/review-me\n"
        "publisher: Test\n"
        "version: v1\n"
        "license: CC-BY\n"
        "review_status: reviewed\n"
        "---\n\n"
        "Current revision requiring review.\n",
        encoding="utf-8",
    )
    entry_id = ingest_file(db, source, ingested_by="curator")
    monkeypatch.setattr(cli_module, "_db", lambda: db)

    result = CliRunner().invoke(app, ["knowledge", "list"])

    assert result.exit_code == 0, result.output
    assert entry_id in result.output
    assert "unreviewed" in result.output


def test_transient_nvd_failure_is_visible_and_does_not_mark_invalid(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "sentinel.sqlite3"
    monkeypatch.setattr(
        cli_module,
        "_db",
        lambda: Database(db_path),
    )
    from sentinel.knowledge import nvd

    def unavailable(_cve):
        raise nvd.NvdError("service unavailable")

    monkeypatch.setattr(nvd, "fetch_cve", unavailable)

    result = CliRunner().invoke(
        app,
        ["knowledge", "sync-cve", "CVE-2024-99999"],
    )

    assert result.exit_code == 1
    assert "UNVERIFIED" in result.output
    check_db = Database(db_path)
    assert (
        check_db.connection.execute(
            "SELECT COUNT(*) FROM cve_entries WHERE cve_id='CVE-2024-99999'"
        ).fetchone()[0]
        == 0
    )
    attempt = check_db.connection.execute(
        "SELECT outcome FROM cve_sync_attempts WHERE cve_id='CVE-2024-99999'"
    ).fetchone()
    assert attempt["outcome"] == "transient_error"
    check_db.close()
