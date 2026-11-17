# SPDX-License-Identifier: Apache-2.0
"""Resource budget: estimated_output_bytes is reserved BEFORE execution.

(v4.1) Prior version passed estimated_bytes=0 to check_available(),
meaning the byte budget could not refuse a single run that would
exceed remaining capacity. Now the request declares an estimate and
the check refuses pre-spawn.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.approval.budget import (
    BudgetExhausted,
    reserve_budget,
    settle_budget,
)
from sentinel.approval.store import (
    ApprovalRecord,
    ApprovalStore,
    target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.sandbox_runner import (
    SandboxRequest,
    run_in_sandbox,
    _current_scope_lock_hash,
    _current_egress_profile_id,
    _current_adapter_code_sha256,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest
import sentinel.runner.builtin_profiles  # noqa: F401


def _make_env(tmp_path, *, byte_budget: int = 1_000_000):
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name="budget-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id,
        raw_value="127.0.0.1",
        canonical_value="127.0.0.1",
        asset_type="ip",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    bin_path = "/bin/true"
    h = hashlib.sha256(Path(bin_path).read_bytes()).hexdigest()
    ManifestStore(db).register(
        ToolManifest(
            tool_name="fake",
            version="1.0",
            executable_path=bin_path,
            executable_sha256=h,
            execution_class=2,
            network_access=True,
            allowed_profiles=("test/passthrough",),
            prohibited=(),
            limits={"max_runtime_seconds": 60},
            output_format="text",
        ),
        actor="test",
    )

    adapter_path = Path("src/sentinel/runner/sandbox_runner.py")
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_budget",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["127.0.0.1"],
        allowed_ports=[80],
        allowed_protocols=["http"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="test/passthrough",
        tool_name="fake",
        tool_version="1.0",
        tool_executable_sha256=h,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
        manifest_hash=ManifestStore(db)
        .get_by_tool_version("fake", "1.0")
        .manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        normalized_arguments_hash="",
        request_rate_budget=5,
        aggregate_request_budget=50,
        aggregate_byte_budget=byte_budget,
        concurrency_budget=1,
        aggregate_runtime_budget=60,
        aggregate_model_token_budget=0,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(minutes=5)).isoformat(),
    )
    ApprovalStore(db).issue(appr)
    return {
        "db": db,
        "eng_id": eng.id,
        "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
    }


def _req(**overrides):
    base = dict(
        hostname="127.0.0.1",
        port=80,
        protocol="http",
        method="GET",
        path="/",
        argv=["/bin/true"],
        timeout_seconds=10,
        operation_profile="test/passthrough",
        profile_params={"argv": ["/bin/true"]},
        requires_target_connection=False,
        estimated_requests=1,
        estimated_output_bytes=0,
    )
    base.update(overrides)
    return SandboxRequest(**base)


def test_zero_estimate_still_reserves_real_capture_cap(tmp_path, monkeypatch):
    """Output estimate metadata cannot disable actual output reservations."""
    env = _make_env(tmp_path, byte_budget=1000)
    import sentinel.runner.sandbox_runner as sr

    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["1.1.1.1"])
    from tests.runner.test_env_and_watchdog_drift import (
        _fake_namespace,
        _FakeProc,
    )

    monkeypatch.setattr(sr, "run_namespace", _fake_namespace)
    monkeypatch.setattr(sr.subprocess, "Popen", lambda *a, **k: _FakeProc(duration=0.1))

    # Byte budget is 1000, estimate is 0 → no refusal even though real
    # output could exceed. This is intentional: adapters that don't
    # declare an estimate retain old behavior.
    result = run_in_sandbox(
        db=env["db"],
        engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="fake",
        adapter_version="1.0",
        request=_req(estimated_output_bytes=0),
        engagements_root=env["engagements_root"],
        adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
        actor="op",
    )
    assert result is not None
    assert result.output_limit_bytes <= 1000
    assert (
        env["db"]
        .connection.execute("SELECT COUNT(*) FROM approval_budget_reservations")
        .fetchone()[0]
        == 0
    )
    env["db"].close()


def test_capture_limit_is_clamped_to_remaining_budget(tmp_path, monkeypatch):
    """Capture stream limits are bounded by the remaining byte budget."""
    env = _make_env(tmp_path, byte_budget=1000)
    import sentinel.runner.sandbox_runner as sr

    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["1.1.1.1"])
    from tests.runner.test_env_and_watchdog_drift import (
        _fake_namespace,
        _FakeProc,
    )

    monkeypatch.setattr(sr, "run_namespace", _fake_namespace)
    monkeypatch.setattr(sr.subprocess, "Popen", lambda *a, **k: _FakeProc(duration=0.1))

    result = run_in_sandbox(
        db=env["db"],
        engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="fake",
        adapter_version="1.0",
        request=_req(estimated_output_bytes=5000),
        engagements_root=env["engagements_root"],
        adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
        actor="op",
    )
    assert result.output_limit_bytes <= 1000
    env["db"].close()


def test_estimate_within_budget_allowed(tmp_path, monkeypatch):
    """Estimated output <= byte budget → passes the reservation check."""
    env = _make_env(tmp_path, byte_budget=1_000_000)
    import sentinel.runner.sandbox_runner as sr

    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["1.1.1.1"])
    from tests.runner.test_env_and_watchdog_drift import (
        _fake_namespace,
        _FakeProc,
    )

    monkeypatch.setattr(sr, "run_namespace", _fake_namespace)
    monkeypatch.setattr(sr.subprocess, "Popen", lambda *a, **k: _FakeProc(duration=0.1))

    result = run_in_sandbox(
        db=env["db"],
        engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="fake",
        adapter_version="1.0",
        request=_req(estimated_output_bytes=500_000),
        engagements_root=env["engagements_root"],
        adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
        actor="op",
    )
    assert result is not None
    env["db"].close()


def test_atomic_reservations_compete_for_remaining_budget(tmp_path):
    env = _make_env(tmp_path, byte_budget=1000)
    db = env["db"]
    first_id, first_cap = reserve_budget(
        db,
        env["approval_id"],
        requests=1,
        requested_bytes=600,
        runtime_seconds=5,
    )
    second_id, second_cap = reserve_budget(
        db,
        env["approval_id"],
        requests=1,
        requested_bytes=600,
        runtime_seconds=5,
    )
    assert first_cap == 600
    assert second_cap == 400
    with pytest.raises(BudgetExhausted, match="output byte budget exhausted"):
        reserve_budget(
            db,
            env["approval_id"],
            requests=1,
            requested_bytes=100,
            runtime_seconds=1,
        )
    settle_budget(
        db, first_id, actual_bytes=300, actual_runtime_seconds=2, spawned=True
    )
    settle_budget(
        db, second_id, actual_bytes=200, actual_runtime_seconds=3, spawned=True
    )
    usage = db.connection.execute(
        "SELECT output_bytes_used, estimated_network_probes, runtime_used_seconds "
        "FROM approval_usage WHERE approval_id=?",
        (env["approval_id"],),
    ).fetchone()
    assert usage["output_bytes_used"] == 500
    assert usage["estimated_network_probes"] == 2
    assert usage["runtime_used_seconds"] == 5
    db.close()
