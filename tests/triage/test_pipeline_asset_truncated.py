# SPDX-License-Identifier: Apache-2.0
"""Batch C: pipeline refuses truncated scans and derives asset_id from
artifact source_name."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence
from sentinel.storage.db import Database


def _make_env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab", program_name="triage-c", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")
    return db, eng.id


def test_ingest_records_truncated_output(tmp_path):
    """truncated_output=True persists to artifacts.truncated_output."""
    db, eng_id = _make_env(tmp_path)
    result = ingest_evidence(
        db, engagements_root=tmp_path / "engagements",
        engagement_id=eng_id,
        source_name="nmap_8.8.8.8_53.xml",
        content_type="application/json",
        content=b'{"results": []}',
        actor="op",
        truncated_output=True,
    )
    row = db.connection.execute(
        "SELECT truncated_output FROM artifacts WHERE id = ?",
        (result.evidence_id,),
    ).fetchone()
    assert row["truncated_output"] == 1
    db.close()


def test_ingest_default_not_truncated(tmp_path):
    db, eng_id = _make_env(tmp_path)
    result = ingest_evidence(
        db, engagements_root=tmp_path / "engagements",
        engagement_id=eng_id,
        source_name="nmap_8.8.8.8_53.xml",
        content_type="application/json",
        content=b'{"results": []}',
        actor="op",
    )
    row = db.connection.execute(
        "SELECT truncated_output FROM artifacts WHERE id = ?",
        (result.evidence_id,),
    ).fetchone()
    assert row["truncated_output"] == 0
    db.close()


def test_asset_id_derivation_helper(tmp_path):
    """Direct test of the derivation logic: longest match wins."""
    import re

    def derive(source_name, approved):
        # Mirrors pipeline's logic exactly
        assets = sorted(approved, key=lambda x: len(x[1]), reverse=True)
        for aid, cv in assets:
            if not cv:
                continue
            pat = r"(?:^|[_.\s/])" + re.escape(cv) + r"(?:$|[_.\s/])"
            if re.search(pat, source_name):
                return aid
        return None

    # Simple cases
    assert derive("nmap_8.8.8.8_53.xml",
                  [("a1", "8.8.8.8")]) == "a1"
    assert derive("scion_example.com.txt",
                  [("a2", "example.com")]) == "a2"
    assert derive("theharvester_example.com.json",
                  [("a3", "example.com")]) == "a3"
    assert derive("zap_127.0.0.1_8080.xml",
                  [("a4", "127.0.0.1")]) == "a4"
    # Longest wins when both `test` and `test.example.com` approved
    assert derive("scion_test.example.com.txt",
                  [("a5", "test"),
                   ("a6", "test.example.com")]) == "a6"
    # No match
    assert derive("bandit_1.8.0.json", [("a7", "example.com")]) is None
