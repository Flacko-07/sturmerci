# SPDX-License-Identifier: Apache-2.0
"""P3-C: gatekeeper_filter re-checks full state on every request."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.approval.store import (
    ApprovalRecord, ApprovalStore, target_asset_ids_hash,
)
from sentinel.approval.state import (
    current_scope_lock_hash, current_policy_hash, current_manifest_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.l7.gatekeeper_filter import make_gatekeeper_filter
from sentinel.l7.proxy import ProxyRequest
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


def _setup(tmp_path, *, policy_bound: bool = False):
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab", program_name="filter-test", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id, raw_value="app.test",
        canonical_value="app.test", asset_type="hostname",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    bin_sha = hashlib.sha256(b"/bin/sh").hexdigest()
    ManifestStore(db).register(ToolManifest(
        tool_name="httpx", version="1.0",
        executable_path="/bin/sh", executable_sha256=bin_sha,
        execution_class=2, network_access=True,
        allowed_profiles=("inventory",),
        prohibited=(), limits={"max_runtime_seconds": 60},
        output_format="jsonl",
    ), actor="test")
    man_hash = ManifestStore(db).get_by_tool_version(
        "httpx", "1.0").manifest_hash

    policy_hash = ""
    if policy_bound:
        now_iso = datetime.now(timezone.utc).isoformat()
        db.connection.execute(
            "INSERT INTO policy_snapshots (id, engagement_id, policy_hash, "
            "raw_text_path, created_at_utc) VALUES (?, ?, ?, ?, ?)",
            ("ps_A", eng.id, "policy_A", "/tmp/p.txt", now_iso),
        )
        policy_hash = "policy_A"

    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_filter",
        engagement_id=eng.id, engagement_state_at_issue="active",
        policy_snapshot_hash=policy_hash,
        scope_lock_hash=current_scope_lock_hash(db, eng.id),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["app.test"],
        allowed_ports=[443], allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="httpx/inventory",
        tool_name="httpx", tool_version="1.0",
        tool_executable_sha256=bin_sha,
        adapter_code_sha256="0" * 64,
        manifest_hash=man_hash,
        egress_profile_id="x",
        normalized_arguments_hash="",
        request_rate_budget=5, aggregate_request_budget=50,
        aggregate_byte_budget=1_000_000, concurrency_budget=1,
        aggregate_runtime_budget=60, aggregate_model_token_budget=0,
        issued_by="op", issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(minutes=5)).isoformat(),
    )
    ApprovalStore(db).issue(appr)
    return db, eng.id, appr.approval_id, aid


def _mk_req():
    return ProxyRequest(
        method="GET", host="app.test", path="/",
        headers={}, port=443,
        http_version="HTTP/1.1", body=b"",
    )


def test_filter_allows_when_state_matches(tmp_path):
    db, _, appr_id, _ = _setup(tmp_path)
    f = make_gatekeeper_filter(db.path, appr_id, cache_ttl=0)
    decision = f(_mk_req())
    assert decision.allow is True, decision.reason
    db.close()


def test_filter_denies_when_engagement_paused(tmp_path):
    db, eng_id, appr_id, _ = _setup(tmp_path)
    f = make_gatekeeper_filter(db.path, appr_id, cache_ttl=0)
    EngagementStore(db).transition(eng_id, "paused", "op")
    decision = f(_mk_req())
    assert decision.allow is False
    assert "engagement_not_active" in decision.reason
    db.close()


def test_filter_denies_when_scope_changes(tmp_path):
    db, eng_id, appr_id, _ = _setup(tmp_path)
    f = make_gatekeeper_filter(db.path, appr_id, cache_ttl=0)
    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng_id, raw_value="new.test",
        canonical_value="new.test", asset_type="hostname",
        discovery_source="t",
    )
    astore.promote_candidate(cid, approved_by="op")
    decision = f(_mk_req())
    assert decision.allow is False
    assert "scope_lock_drift" in decision.reason
    db.close()


def test_filter_denies_when_manifest_changes(tmp_path):
    db, _, appr_id, _ = _setup(tmp_path)
    f = make_gatekeeper_filter(db.path, appr_id, cache_ttl=0)
    db.connection.execute(
        "DELETE FROM tool_manifests WHERE tool_name = 'httpx'"
    )
    db.commit()
    ManifestStore(db).register(ToolManifest(
        tool_name="httpx", version="1.0",
        executable_path="/bin/sh",
        executable_sha256="0" * 64,
        execution_class=2, network_access=True,
        allowed_profiles=("inventory",),
        prohibited=(), limits={"max_runtime_seconds": 60},
        output_format="jsonl",
    ), actor="test")
    decision = f(_mk_req())
    assert decision.allow is False
    assert "manifest_drift" in decision.reason
    db.close()


def test_filter_denies_when_policy_bound_and_changed(tmp_path):
    db, eng_id, appr_id, _ = _setup(tmp_path, policy_bound=True)
    f = make_gatekeeper_filter(db.path, appr_id, cache_ttl=0)
    d1 = f(_mk_req())
    assert d1.allow is True, d1.reason

    now_iso = datetime.now(timezone.utc).isoformat()
    db.connection.execute(
        "INSERT INTO policy_snapshots (id, engagement_id, policy_hash, "
        "raw_text_path, created_at_utc) VALUES (?, ?, ?, ?, ?)",
        ("ps_B", eng_id, "policy_B", "/tmp/p.txt", now_iso),
    )
    db.commit()
    d2 = f(_mk_req())
    assert d2.allow is False
    assert "policy_drift" in d2.reason
    db.close()
