# SPDX-License-Identifier: Apache-2.0
import pytest

"""Gate 2: candidate/approved separation, target-hash drift."""
from sentinel.assets.store import AssetStore
from sentinel.approval.store import ApprovalStore, ApprovalRecord, target_asset_ids_hash
from sentinel.storage.db import Database


def test_new_candidate_does_not_enter_approved_set(tmp_path):
    a = AssetStore(tmp_path / "a.db")
    a.add_candidate(engagement_id="eng1", raw_value="new.example.test",
                    canonical_value="new.example.test",
                    asset_type="hostname", discovery_source="passive")
    assert a.approved_ids("eng1") == []
    a.close()


def test_promote_changes_target_hash(tmp_path):
    a = AssetStore(tmp_path / "a.db")
    cid = a.add_candidate(engagement_id="eng1", raw_value="a.test",
                          canonical_value="a.test", asset_type="hostname",
                          discovery_source="passive")
    h0 = a.current_target_hash("eng1")
    a.promote_candidate(cid, approved_by="op")
    h1 = a.current_target_hash("eng1")
    assert h0 != h1
    a.close()


def test_prior_approval_invalidated_by_new_asset(tmp_path):
    """G2-T03: an approval issued before a new asset was promoted cannot be
    used to target that asset (its target set hash no longer matches)."""
    from sentinel.approval.gatekeeper import check_request, RequestContext

    a = AssetStore(tmp_path / "a.db")
    s = ApprovalStore(tmp_path / "a.db")

    # Issue an approval against the empty approved set
    empty_hash = a.current_target_hash("eng1")
    rec = ApprovalRecord(
        approval_id="appr_1", engagement_id="eng1",
        engagement_state_at_issue="active",
        policy_snapshot_hash="p", scope_lock_hash="s",
        target_asset_ids=a.approved_ids("eng1"),
        target_asset_ids_hash=empty_hash,
        canonical_hostnames=["a.test"],
        allowed_ports=[443], allowed_protocols=["https"],
        allowed_http_methods=["GET"], allowed_path_profile="default",
        operation_profile_id="p1", tool_name="t", tool_version="1",
        tool_executable_sha256="e", adapter_code_sha256="a",
        manifest_hash="m", egress_profile_id="eg",
        normalized_arguments_hash="args",
        request_rate_budget=10, aggregate_request_budget=100,
        aggregate_byte_budget=1_000_000, concurrency_budget=1,
        aggregate_runtime_budget=60, aggregate_model_token_budget=10_000,
        issued_by="op", issued_at_utc="2030-01-01T00:00:00+00:00",
        expires_at_utc="2030-01-01T01:00:00+00:00",
    )
    s.issue(rec)

    # Now promote a new asset
    cid = a.add_candidate(engagement_id="eng1", raw_value="b.test",
                          canonical_value="b.test", asset_type="hostname",
                          discovery_source="passive")
    aid = a.promote_candidate(cid, approved_by="op")

    # Attempting to reach the new asset with the old approval is denied
    ctx = RequestContext(
        engagement_id="eng1", engagement_state="active",
        policy_snapshot_hash="p", scope_lock_hash="s",
        target_asset_ids_hash=a.current_target_hash("eng1"),
        target_asset_id=aid,
        tool_executable_sha256="e", adapter_code_sha256="a",
        manifest_hash="m", egress_profile_id="eg",
        port=443, protocol="https", http_method="GET", path="/",
    )
    d = check_request(s, rec.approval_id, ctx)
    assert not d.allowed
    assert "target set" in d.reason
    a.close()
    s.close()

@pytest.fixture(autouse=True)
def _seed_engagement(tmp_path):
    """Seed eng1 so FK constraints on candidate/approved assets pass."""
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
