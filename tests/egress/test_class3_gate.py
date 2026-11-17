# SPDX-License-Identifier: Apache-2.0
"""ECR v1.0.2 Class 3 authorization gate tests."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.approval.store import (
    ApprovalRecord,
    ApprovalStore,
    target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner import sandbox_runner as _sr
from sentinel.runner.sandbox_runner import (
    SandboxDenied,
    SandboxRequest,
    run_in_sandbox,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest
from sentinel.runner.profiles import params_hash


pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="requires root for namespace creation",
)


ECHO_BIN = "/bin/echo"


def _echo_sha() -> str:
    return hashlib.sha256(Path(ECHO_BIN).read_bytes()).hexdigest()


def _build_env(tmp_path, *, intrusive=False, lab=False, platform="lab"):
    """Build a test env with a Class 3 manifest."""
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform=platform,
        program_name="class3-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id,
        raw_value="probe.test",
        canonical_value="probe.test",
        asset_type="hostname",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    echo_sha = _echo_sha()
    manifest_store = ManifestStore(db)
    m = ToolManifest(
        tool_name="class3_echo",
        version="1.0.0",
        executable_path=ECHO_BIN,
        executable_sha256=echo_sha,
        execution_class=3,
        network_access=True,  # Class 3
        allowed_profiles=("test", "test/echo", "test/exploit_passthrough"),
        prohibited=(),
        limits={"max_runtime_seconds": 30},
        output_format="text",
    )
    registered = manifest_store.register(m, actor="op")

    from sentinel.runner.sandbox_runner import (
        _current_scope_lock_hash,
        _current_egress_profile_id,
        _current_adapter_code_sha256,
    )

    fake_adapter = Path(__file__).parent.parent / "fixtures" / "fake_adapter.py"
    scope = _current_scope_lock_hash(db, eng.id, "")
    egress = _current_egress_profile_id()
    adapter_hash = _current_adapter_code_sha256(fake_adapter)

    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_class3",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="p",
        scope_lock_hash=scope,
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["probe.test"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="test/exploit_passthrough",
        tool_name="class3_echo",
        tool_version="1.0.0",
        tool_executable_sha256=echo_sha,
        adapter_code_sha256=adapter_hash,
        manifest_hash=registered.manifest_hash,
        egress_profile_id=egress,
        normalized_arguments_hash=params_hash(
            {
                "argv": [ECHO_BIN, "class3-hello"],
            }
        ),
        request_rate_budget=10,
        aggregate_request_budget=100,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=60,
        aggregate_model_token_budget=10_000,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
        intrusive_authorized=intrusive,
        lab_environment=lab,
        profile_params={"argv": [ECHO_BIN, "class3-hello"]},
    )
    ApprovalStore(db).issue(appr)

    return {
        "db": db,
        "eng_id": eng.id,
        "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
        "adapter_code_path": fake_adapter,
    }


def _stub_resolver(monkeypatch, ip: str = "1.1.1.1") -> None:
    monkeypatch.setattr(_sr, "_resolve_hostname", lambda h: [ip])


def _mk_request(argv=None, **overrides) -> SandboxRequest:
    # (P0.1) mandatory profile. test/exploit_passthrough is class 3 and
    # allows argv[0] override so the fixture's ECHO_BIN path works with
    # either the class-3 fixture manifest or the plain echo_test one.
    _argv = list(argv) if argv else [ECHO_BIN, "class3-hello"]
    base = dict(
        hostname="probe.test",
        port=443,
        protocol="https",
        method="GET",
        path="/",
        argv=_argv,
        timeout_seconds=15,
        operation_profile="test/exploit_passthrough",
        profile_params={"argv": _argv},
    )
    base.update(overrides)
    return SandboxRequest(**base)


def test_class3_refused_without_intrusive_auth(tmp_path, monkeypatch):
    """Class 3 + no intrusive_authorized -> refused."""
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, intrusive=False, lab=True)
    try:
        with pytest.raises(SandboxDenied, match="intrusive"):
            run_in_sandbox(
                db=env["db"],
                engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                adapter_name="class3_echo",
                adapter_version="1.0.0",
                request=_mk_request(),
                adapter_code_path=env["adapter_code_path"],
                engagements_root=env["engagements_root"],
                actor="op",
            )
        # Audit event written
        row = (
            env["db"]
            .connection.execute(
                "SELECT details_json FROM audit_events "
                "WHERE event_type = 'sandbox_denied' "
                "AND details_json LIKE '%class3_no_intrusive_auth%'"
            )
            .fetchone()
        )
        assert row is not None
    finally:
        env["db"].close()


def test_class3_refused_without_lab_environment(tmp_path, monkeypatch):
    """Class 3 + intrusive_authorized but no lab_environment -> refused."""
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, intrusive=True, lab=False)
    try:
        with pytest.raises(SandboxDenied, match="lab_environment"):
            run_in_sandbox(
                db=env["db"],
                engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                adapter_name="class3_echo",
                adapter_version="1.0.0",
                request=_mk_request(),
                adapter_code_path=env["adapter_code_path"],
                engagements_root=env["engagements_root"],
                actor="op",
            )
    finally:
        env["db"].close()


def test_class3_runs_when_both_flags_set(tmp_path, monkeypatch):
    """Class 3 + intrusive_authorized=True + lab_environment=True -> runs."""
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, intrusive=True, lab=True)
    try:
        result = run_in_sandbox(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="class3_echo",
            adapter_version="1.0.0",
            request=_mk_request(),
            adapter_code_path=env["adapter_code_path"],
            engagements_root=env["engagements_root"],
            actor="op",
        )
        assert result.exit_code == 0
        assert "class3-hello" in result.stdout
    finally:
        env["db"].close()
