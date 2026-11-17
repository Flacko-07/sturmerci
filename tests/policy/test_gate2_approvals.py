# SPDX-License-Identifier: Apache-2.0
"""Gate 2: approval lifecycle + per-request gatekeeper."""
from datetime import datetime, timedelta, timezone
import pytest

from sentinel.approval.store import (
    ApprovalRecord, ApprovalStore, target_asset_ids_hash,
)
from sentinel.approval.gatekeeper import (
    RequestContext, check_request,
)

from sentinel.storage.db import Database


def _record(**overrides) -> ApprovalRecord:
    base = dict(
        approval_id="appr_test_" + "a" * 8,
        engagement_id="eng1",
        engagement_state_at_issue="active",
        policy_snapshot_hash="pol_abc",
        scope_lock_hash="sl_def",
        target_asset_ids=["aa_1", "aa_2"],
        target_asset_ids_hash=target_asset_ids_hash(["aa_1", "aa_2"]),
        canonical_hostnames=["app.example.test"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="httpx_http_inventory",
        tool_name="httpx",
        tool_version="1.6.0",
        tool_executable_sha256="exe_hash",
        adapter_code_sha256="adp_hash",
        manifest_hash="man_hash",
        egress_profile_id="egress_default",
        normalized_arguments_hash="args_hash",
        request_rate_budget=10,
        aggregate_request_budget=1000,
        aggregate_byte_budget=10_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=600,
        aggregate_model_token_budget=200_000,
        issued_by="op",
        issued_at_utc=datetime.now(timezone.utc).isoformat(),
        expires_at_utc=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    )
    base.update(overrides)
    return ApprovalRecord(**base)


def _ctx(**overrides) -> RequestContext:
    base = dict(
        engagement_id="eng1",
        engagement_state="active",
        policy_snapshot_hash="pol_abc",
        scope_lock_hash="sl_def",
        target_asset_ids_hash=target_asset_ids_hash(["aa_1", "aa_2"]),
        target_asset_id="aa_1",
        tool_executable_sha256="exe_hash",
        adapter_code_sha256="adp_hash",
        manifest_hash="man_hash",
        egress_profile_id="egress_default",
        port=443,
        protocol="https",
        http_method="GET",
        path="/",
    )
    base.update(overrides)
    return RequestContext(**base)


def test_issue_and_get(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    s.issue(_record())
    got = s.get("appr_test_" + "a" * 8)
    assert got is not None
    assert got.engagement_id == "eng1"
    s.close()


def test_check_passes_when_everything_matches(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx())
    assert d.allowed, d.reason
    s.close()


# --- G2-T01: policy/scope drift ---

def test_policy_hash_drift_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(policy_snapshot_hash="changed"))
    assert not d.allowed and "policy" in d.reason
    s.close()


def test_scope_lock_drift_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(scope_lock_hash="changed"))
    assert not d.allowed and "scope" in d.reason
    s.close()


# --- G2-T02: tool/manifest/engagement drift ---

def test_target_set_drift_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    new_hash = target_asset_ids_hash(["aa_1", "aa_2", "aa_3"])
    d = check_request(s, rec.approval_id, _ctx(target_asset_ids_hash=new_hash))
    assert not d.allowed and "target set" in d.reason
    s.close()


def test_tool_executable_drift_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(tool_executable_sha256="new"))
    assert not d.allowed and "tool executable" in d.reason
    s.close()


def test_adapter_drift_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(adapter_code_sha256="new"))
    assert not d.allowed and "adapter" in d.reason
    s.close()


def test_manifest_drift_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(manifest_hash="new"))
    assert not d.allowed and "manifest" in d.reason
    s.close()


def test_engagement_state_drift_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(engagement_state="paused"))
    assert not d.allowed and "engagement" in d.reason
    s.close()


# --- G2-T04: expiry + revocation ---

def test_expired_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    rec = _record(expires_at_utc=past); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx())
    assert not d.allowed and "expired" in d.reason
    s.close()


def test_revoked_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    s.revoke(rec.approval_id)
    d = check_request(s, rec.approval_id, _ctx())
    assert not d.allowed and "revoked" in d.reason
    s.close()


# --- G2-T02 extras: port/protocol/method ---

def test_port_not_allowed(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(port=22))
    assert not d.allowed and "port" in d.reason
    s.close()


def test_protocol_not_allowed(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(protocol="http"))
    assert not d.allowed and "protocol" in d.reason
    s.close()


def test_method_not_allowed(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(http_method="DELETE"))
    assert not d.allowed and "method" in d.reason
    s.close()


# --- G2-T03: candidate cannot be consumed by prior approval ---

def test_target_asset_not_in_approved_set_denied(tmp_path):
    s = ApprovalStore(tmp_path / "a.db")
    rec = _record(); s.issue(rec)
    d = check_request(s, rec.approval_id, _ctx(target_asset_id="aa_other"))
    assert not d.allowed and "not in approved set" in d.reason
    s.close()

@pytest.fixture(autouse=True)
def _seed_engagement(tmp_path):
    """Seed eng1 so FK constraints on the approvals table pass.

    Milestone 2A added engagement_id REFERENCES engagements(id); the
    original tests inserted approvals with a synthetic engagement_id
    that had no row in engagements. This fixture creates that row.
    """
    db = Database(tmp_path / "a.db")
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO engagements "
            "(id, platform, program_name, policy_url, state, "
            " created_at_utc, updated_at_utc, created_by) "
            "VALUES ('eng1', 'hackerone', 'test', NULL, 'active', "
            "        'now', 'now', 'op')"
        )
    db.close()


def test_all_approval_record_fields_round_trip():
    """Every ApprovalRecord field must map to a column in _COLUMNS.

    This catches the class of bug where a new field is added to the
    dataclass but not to the schema column list (or vice versa), which
    manifests as silent empty values at read time.
    """
    import dataclasses
    from sentinel.approval.store import ApprovalRecord, _COLUMNS
    fields = {f.name for f in dataclasses.fields(ApprovalRecord)}
    # Fields serialized as JSON get a "_json" suffix in the column name
    json_pairs = {
        "allowed_http_methods", "allowed_protocols", "allowed_ports",
        "canonical_hostnames", "target_asset_ids",
        "approved_infrastructure_endpoints", "allowed_path_prefixes",
        "profile_params",
    }
    for field in fields:
        col = field + "_json" if field in json_pairs else field
        assert col in _COLUMNS, (
            f"dataclass field {field!r} maps to column {col!r}, "
            f"which is missing from _COLUMNS"
        )
