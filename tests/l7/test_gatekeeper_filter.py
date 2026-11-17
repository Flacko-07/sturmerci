# SPDX-License-Identifier: Apache-2.0
"""Gatekeeper filter tests (M7.2b)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.approval.store import (
    ApprovalRecord,
    ApprovalStore,
    target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.l7.gatekeeper_filter import (
    make_gatekeeper_filter,
    path_matches_profile,
)
from sentinel.l7.proxy import ProxyRequest
from sentinel.storage.db import Database


# --- path_matches_profile (pure function) ---


def test_profile_default_allows_any_path():
    assert path_matches_profile("/", "default")
    assert path_matches_profile("/api/v1/users", "default")
    assert path_matches_profile("/random", "DEFAULT")


def test_profile_empty_equals_default():
    assert path_matches_profile("/any/path", "")
    assert path_matches_profile("/", None)  # type: ignore[arg-type]


def test_profile_prefix_exact():
    assert path_matches_profile("/api/v1", "/api/v1")


def test_profile_prefix_subpath():
    assert path_matches_profile("/api/v1/users", "/api/v1")
    assert path_matches_profile("/api/v1/users/42", "/api/v1")


def test_profile_prefix_segment_boundary():
    # Critical: /api/v1 must NOT match /api/v10 or /apix
    assert not path_matches_profile("/api/v10", "/api/v1")
    assert not path_matches_profile("/apix", "/api/v1")


def test_profile_prefix_trailing_slash_normalized():
    assert path_matches_profile("/api/v1/users", "/api/v1/")


def test_profile_root_allows_all():
    assert path_matches_profile("/", "/")
    assert path_matches_profile("/any/path", "/")


def test_profile_non_slash_path_denied():
    assert not path_matches_profile("relative/path", "/api")


# --- fixtures for filter tests ---


def _build_env(tmp_path, *, method="GET", path_profile="default", path_prefixes=None):
    # Derive prefixes from the profile when it looks like a path.
    # Mirrors the migration 0005 backfill. Tests that need to exercise
    # "restricted with no prefixes" (config error) pass path_prefixes=[].
    if path_prefixes is None:
        if path_profile and path_profile.startswith("/"):
            path_prefixes = [path_profile]
        else:
            path_prefixes = []
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name="filter-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    asset_store = AssetStore(db)
    cid = asset_store.add_candidate(
        engagement_id=eng.id,
        raw_value="probe.test",
        canonical_value="probe.test",
        asset_type="hostname",
        discovery_source="test",
    )
    asset_id = asset_store.promote_candidate(cid, approved_by="op")

    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_filter_test",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="p",
        scope_lock_hash="",
        target_asset_ids=[asset_id],
        target_asset_ids_hash=target_asset_ids_hash([asset_id]),
        canonical_hostnames=["probe.test"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=[method],
        allowed_path_profile=path_profile,
        allowed_path_prefixes=path_prefixes,
        operation_profile_id="test",
        tool_name="httpx",
        tool_version="1.6.10",
        tool_executable_sha256="e" * 64,
        adapter_code_sha256="a" * 64,
        manifest_hash="" * 64,
        egress_profile_id="eg",
        normalized_arguments_hash="args",
        request_rate_budget=10,
        aggregate_request_budget=100,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=60,
        aggregate_model_token_budget=10_000,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
    )
    ApprovalStore(db).issue(appr)
    return db, appr.approval_id


def _req(method="GET", path="/", host="probe.test", port=443):
    return ProxyRequest(
        method=method,
        path=path,
        http_version="HTTP/1.1",
        host=host,
        port=port,
        headers=(),
        body=b"",
    )


# --- filter tests ---


def test_filter_allows_matching_method_and_path(tmp_path):
    db, appr_id = _build_env(tmp_path, method="GET", path_profile="default")
    try:
        f = make_gatekeeper_filter(db, appr_id, cache_ttl=0)
        d = f(_req(method="GET", path="/"))
        assert d.allow is True
    finally:
        db.close()


def test_filter_denies_wrong_method(tmp_path):
    db, appr_id = _build_env(tmp_path, method="GET")
    try:
        f = make_gatekeeper_filter(db, appr_id, cache_ttl=0)
        d = f(_req(method="POST"))
        assert d.allow is False
        assert "method_not_allowed" in d.reason
    finally:
        db.close()


def test_filter_denies_path_outside_profile(tmp_path):
    db, appr_id = _build_env(
        tmp_path,
        method="GET",
        path_profile="/api/v1",
        path_prefixes=["/api/v1"],
    )
    try:
        f = make_gatekeeper_filter(db, appr_id, cache_ttl=0)
        # In profile
        assert f(_req(path="/api/v1/users")).allow is True
        # Outside profile
        d = f(_req(path="/admin"))
        assert d.allow is False
        # M7.2c: filter now uses the prefix-list code path in restricted mode
        assert "path_out_of_prefixes" in d.reason
        assert "/api/v1" in d.reason
    finally:
        db.close()


def test_filter_denies_when_approval_revoked(tmp_path):
    db, appr_id = _build_env(tmp_path)
    try:
        f = make_gatekeeper_filter(db, appr_id, cache_ttl=0)
        # Initially allowed
        assert f(_req(method="GET", path="/")).allow is True
        # Revoke
        ApprovalStore(db).revoke(appr_id)
        # Now denied
        d = f(_req(method="GET", path="/"))
        assert d.allow is False
        assert d.reason == "approval_revoked"
    finally:
        db.close()


def test_filter_denies_when_approval_missing(tmp_path):
    db, _appr_id = _build_env(tmp_path)
    try:
        f = make_gatekeeper_filter(db, "nonexistent_approval", cache_ttl=0)
        d = f(_req())
        assert d.allow is False
        assert d.reason == "approval_not_found"
    finally:
        db.close()


def test_filter_case_insensitive_method(tmp_path):
    db, appr_id = _build_env(tmp_path, method="GET")
    try:
        f = make_gatekeeper_filter(db, appr_id, cache_ttl=0)
        assert f(_req(method="GET")).allow is True
        assert f(_req(method="get")).allow is True
        assert f(_req(method="GeT")).allow is True
    finally:
        db.close()


def test_filter_methods_list(tmp_path):
    db, appr_id = _build_env(tmp_path, method="GET")
    try:
        # Add HEAD to allowed methods
        with db.transaction() as conn:
            conn.execute(
                "UPDATE approvals SET allowed_http_methods_json = ? "
                "WHERE approval_id = ?",
                ('["GET","HEAD"]', appr_id),
            )
        f = make_gatekeeper_filter(db, appr_id, cache_ttl=0)
        assert f(_req(method="GET")).allow is True
        assert f(_req(method="HEAD")).allow is True
        assert f(_req(method="POST")).allow is False
    finally:
        db.close()


# --- M7.2c: path_matches_prefixes ---


def test_prefixes_empty_denies():
    from sentinel.l7.gatekeeper_filter import path_matches_prefixes

    assert path_matches_prefixes("/", []) is False
    assert path_matches_prefixes("/api", []) is False


def test_prefixes_single_match():
    from sentinel.l7.gatekeeper_filter import path_matches_prefixes

    assert path_matches_prefixes("/api/v1/users", ["/api"]) is True
    assert path_matches_prefixes("/api", ["/api"]) is True
    assert path_matches_prefixes("/admin", ["/api"]) is False


def test_prefixes_multiple_match():
    from sentinel.l7.gatekeeper_filter import path_matches_prefixes

    prefixes = ["/api/v1", "/health"]
    assert path_matches_prefixes("/api/v1/users", prefixes) is True
    assert path_matches_prefixes("/health", prefixes) is True
    assert path_matches_prefixes("/admin", prefixes) is False


def test_prefixes_segment_boundary():
    from sentinel.l7.gatekeeper_filter import path_matches_prefixes

    assert path_matches_prefixes("/api/v10", ["/api/v1"]) is False
    assert path_matches_prefixes("/apix", ["/api"]) is False


def test_prefixes_query_string_stripped():
    from sentinel.l7.gatekeeper_filter import path_matches_prefixes

    assert path_matches_prefixes("/api/v1/users?id=1", ["/api/v1"]) is True
    assert path_matches_prefixes("/admin?x=1", ["/api"]) is False


def test_prefixes_root_allows_all():
    from sentinel.l7.gatekeeper_filter import path_matches_prefixes

    assert path_matches_prefixes("/any/path", ["/"]) is True


# --- M7.2c: filter uses prefixes in restricted mode ---


def test_filter_restricted_mode_uses_prefixes(tmp_path):
    """Approval with profile='/api' + prefixes=['/api'] allows /api/*,
    denies /admin."""
    from sentinel.l7.gatekeeper_filter import make_gatekeeper_filter
    from sentinel.l7.proxy import ProxyRequest

    db = Database(tmp_path / "f.db")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name="p",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "e",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")
    asst = AssetStore(db)
    cid = asst.add_candidate(
        engagement_id=eng.id,
        raw_value="probe.test",
        canonical_value="probe.test",
        asset_type="hostname",
        discovery_source="t",
    )
    aid = asst.promote_candidate(cid, approved_by="op")

    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_paths",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="p",
        scope_lock_hash="",
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["probe.test"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="/api",
        allowed_path_prefixes=["/api"],
        operation_profile_id="x",
        tool_name="httpx",
        tool_version="1.6.10",
        tool_executable_sha256="e" * 64,
        adapter_code_sha256="a" * 64,
        manifest_hash="" * 64,
        egress_profile_id="eg",
        normalized_arguments_hash="args",
        request_rate_budget=10,
        aggregate_request_budget=100,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=60,
        aggregate_model_token_budget=10_000,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
    )
    ApprovalStore(db).issue(appr)

    filt = make_gatekeeper_filter(db, "appr_paths", cache_ttl=0)

    def req(path):
        return ProxyRequest(
            method="GET",
            path=path,
            http_version="HTTP/1.1",
            host="probe.test",
            port=443,
            headers=(),
            body=b"",
        )

    assert filt(req("/api/v1/users")).allow is True
    assert filt(req("/api/health")).allow is True
    d = filt(req("/admin"))
    assert d.allow is False
    assert "path_out_of_prefixes" in d.reason
    db.close()


def test_filter_restricted_with_no_prefixes_denies_all(tmp_path):
    """Restricted profile + empty prefixes -> configuration error, deny."""
    from sentinel.l7.gatekeeper_filter import make_gatekeeper_filter

    db = Database(tmp_path / "f.db")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name="p",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "e",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")
    asst = AssetStore(db)
    cid = asst.add_candidate(
        engagement_id=eng.id,
        raw_value="x.test",
        canonical_value="x.test",
        asset_type="hostname",
        discovery_source="t",
    )
    aid = asst.promote_candidate(cid, approved_by="op")

    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_no_prefixes",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="p",
        scope_lock_hash="",
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["x.test"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="/api",
        allowed_path_prefixes=[],  # deliberately empty -> misconfig
        operation_profile_id="x",
        tool_name="httpx",
        tool_version="1.6.10",
        tool_executable_sha256="e" * 64,
        adapter_code_sha256="a" * 64,
        manifest_hash="" * 64,
        egress_profile_id="eg",
        normalized_arguments_hash="args",
        request_rate_budget=10,
        aggregate_request_budget=100,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=60,
        aggregate_model_token_budget=10_000,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
    )
    ApprovalStore(db).issue(appr)

    filt = make_gatekeeper_filter(db, "appr_no_prefixes", cache_ttl=0)
    from sentinel.l7.proxy import ProxyRequest

    d = filt(
        ProxyRequest(
            method="GET",
            path="/any",
            http_version="HTTP/1.1",
            host="x.test",
            port=443,
            headers=(),
            body=b"",
        )
    )
    assert d.allow is False
    assert "no_prefixes" in d.reason
    db.close()


# --- M7-P0-D: path canonicalization bypass closed ---


@pytest.mark.parametrize(
    "bypass",
    [
        "/api/../admin",
        "/api/%2e%2e/admin",
        "/api/%2E%2E/admin",
        "/api%2f..%2fadmin",
        "/api\\..\\admin",
        "/api/%252e%252e/admin",  # double-encoded
        "/api/././../admin",
        "//api/../admin",
        "/api\x00/../admin",
        "/api/..%2fadmin",
    ],
)
def test_m7p0d_path_bypass_denied(bypass):
    from sentinel.l7.gatekeeper_filter import path_matches_prefixes

    assert path_matches_prefixes(bypass, ["/api"]) is False


def test_m7p0d_valid_paths_still_match():
    from sentinel.l7.gatekeeper_filter import path_matches_prefixes

    assert path_matches_prefixes("/api", ["/api"]) is True
    assert path_matches_prefixes("/api/v1/users", ["/api"]) is True
    assert path_matches_prefixes("/api/admin?x=1", ["/api"]) is True
    assert path_matches_prefixes("/api/users%20name", ["/api"]) is True
    assert path_matches_prefixes("/api/.hidden", ["/api"]) is True


# --- M7-06: expiry re-checked per request ---


def test_m7p06_expired_approval_denied_per_request(tmp_path):
    """M7-06: the filter re-checks expiry on every request.

    Cache TTL is a bounded staleness window by design (see design doc).
    What matters for M7-06 is that the expiry CHECK exists and fires
    when the approval is actually expired. cache_ttl=0 forces the check
    path without cache staleness.
    """
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    from sentinel.l7.gatekeeper_filter import make_gatekeeper_filter

    db, appr_id = _build_env(tmp_path, method="GET", path_profile="default")
    try:
        # Expire the approval BEFORE creating the filter
        past = (_dt.now(_tz.utc) - _td(minutes=1)).isoformat()
        with db.transaction() as conn:
            conn.execute(
                "UPDATE approvals SET expires_at_utc = ? WHERE approval_id = ?",
                (past, appr_id),
            )

        f = make_gatekeeper_filter(db, appr_id, cache_ttl=0)
        d = f(_req(method="GET", path="/"))
        assert d.allow is False
        assert d.reason == "approval_expired"
    finally:
        db.close()


def test_m7p06_cache_staleness_is_bounded(tmp_path):
    """Cache staleness is bounded by cache_ttl -- this is a documented
    tradeoff, not a defect. Verify: with ttl=0, DB mutations are seen
    immediately."""
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    from sentinel.l7.gatekeeper_filter import make_gatekeeper_filter

    db, appr_id = _build_env(tmp_path, method="GET", path_profile="default")
    try:
        f = make_gatekeeper_filter(db, appr_id, cache_ttl=0)
        d1 = f(_req(method="GET", path="/"))
        assert d1.allow is True

        # Expire in DB
        past = (_dt.now(_tz.utc) - _td(minutes=1)).isoformat()
        with db.transaction() as conn:
            conn.execute(
                "UPDATE approvals SET expires_at_utc = ? WHERE approval_id = ?",
                (past, appr_id),
            )

        d2 = f(_req(method="GET", path="/"))
        assert d2.allow is False
        assert d2.reason == "approval_expired"
    finally:
        db.close()
