# SPDX-License-Identifier: Apache-2.0
"""P0.1 / P0.3 enforcement tests.

These tests exercise the runner's central enforcement layer directly
(no mocks of run_in_sandbox). They fail before namespace creation, so
they run without root.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sentinel.runner.builtin_profiles  # noqa: F401  registers test/* profiles
from sentinel.approval.store import (
    ApprovalRecord,
    ApprovalStore,
    target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.sandbox_runner import (
    SandboxDenied,
    SandboxRequest,
    run_in_sandbox,
)
from sentinel.runner.sandbox_runner import (
    _current_scope_lock_hash,
    _current_egress_profile_id,
    _current_adapter_code_sha256,
)
from sentinel.runner.profiles import params_hash
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


def _make_env(
    tmp_path,
    *,
    allowed_profiles=("test/echo",),
    manifest_class=2,
    prohibited=(),
    intrusive=False,
    lab=False,
):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="enforce-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id,
        raw_value="127.0.0.1",
        canonical_value="127.0.0.1",
        asset_type="ip",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    fake_binary = "/bin/true"
    h = hashlib.sha256(Path(fake_binary).read_bytes()).hexdigest()
    ManifestStore(db).register(
        ToolManifest(
            tool_name="fake",
            version="1.0",
            executable_path=fake_binary,
            executable_sha256=h,
            execution_class=manifest_class,
            network_access=True,
            allowed_profiles=tuple(allowed_profiles),
            prohibited=tuple(prohibited),
            limits={"max_runtime_seconds": 60, "max_output_megabytes": 5},
            output_format="text",
        ),
        actor="test",
    )

    adapter_path = Path("src/sentinel/runner/sandbox_runner.py")
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_enforce",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="p",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["127.0.0.1"],
        allowed_ports=[18080],
        allowed_protocols=["http"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="",
        tool_name="fake",
        tool_version="1.0",
        tool_executable_sha256=h,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
        manifest_hash=ManifestStore(db)
        .get_by_tool_version("fake", "1.0")
        .manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        normalized_arguments_hash="",
        request_rate_budget=10,
        aggregate_request_budget=100,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=60,
        aggregate_model_token_budget=0,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
        intrusive_authorized=intrusive,
        lab_environment=lab,
    )
    ApprovalStore(db).issue(appr)
    return {
        "db": db,
        "eng_id": eng.id,
        "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
    }


def test_network_manifest_requires_operation_profile(tmp_path):
    """P0.1: network manifests must declare an operation profile."""
    env = _make_env(tmp_path)
    req = SandboxRequest(
        hostname="127.0.0.1",
        port=18080,
        protocol="http",
        method="GET",
        path="/",
        argv=["/bin/true"],
        # NO operation_profile
    )
    with pytest.raises(SandboxDenied, match="operation_profile"):
        run_in_sandbox(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="fake",
            adapter_version="1.0",
            request=req,
            engagements_root=env["engagements_root"],
            adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
            actor="test",
        )
    env["db"].close()


def test_profile_must_be_in_manifest_allowed_profiles(tmp_path):
    """P0.1: operation_profile must be in manifest.allowed_profiles."""
    env = _make_env(tmp_path, allowed_profiles=("test/echo",))
    req = SandboxRequest(
        hostname="127.0.0.1",
        port=18080,
        protocol="http",
        method="GET",
        path="/",
        argv=["/bin/true", "exploit"],
        operation_profile="test/exploit",  # NOT in allowed_profiles
        profile_params={},
    )
    with pytest.raises(SandboxDenied, match="not in manifest"):
        run_in_sandbox(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="fake",
            adapter_version="1.0",
            request=req,
            engagements_root=env["engagements_root"],
            adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
            actor="test",
        )
    env["db"].close()


def test_manifest_prohibited_enforced_centrally(tmp_path):
    """P0.1: manifest.prohibited enforced regardless of the profile."""
    env = _make_env(
        tmp_path,
        allowed_profiles=("test/echo",),
        prohibited=("hello",),  # test/echo emits "hello" as argv[1]
    )
    req = SandboxRequest(
        hostname="127.0.0.1",
        port=18080,
        protocol="http",
        method="GET",
        path="/",
        argv=["/bin/true", "hello"],
        operation_profile="test/echo",
        profile_params={},
    )
    with pytest.raises(SandboxDenied, match="prohibited"):
        run_in_sandbox(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="fake",
            adapter_version="1.0",
            request=req,
            engagements_root=env["engagements_root"],
            adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
            actor="test",
        )
    env["db"].close()


def test_class2_manifest_cannot_host_class3_profile(tmp_path):
    """P0.3: a class-2 manifest cannot downgrade a class-3 profile.

    6B is bypassed by binding the approval to the profile under test —
    the point here is the *profile-class* gate, not the approval binding.
    """
    env = _make_env(
        tmp_path,
        manifest_class=2,
        allowed_profiles=("test/exploit",),
        intrusive=False,
        lab=False,
    )
    # Bind approval to the profile under test so 6B passes
    env["db"].connection.execute(
        "UPDATE approvals SET operation_profile_id = ?, "
        "normalized_arguments_hash = ? "
        "WHERE approval_id = ?",
        ("test/exploit", params_hash({}), env["approval_id"]),
    )
    env["db"].commit()
    req = SandboxRequest(
        hostname="127.0.0.1",
        port=18080,
        protocol="http",
        method="GET",
        path="/",
        argv=["/bin/true", "exploit"],
        operation_profile="test/exploit",
        profile_params={},
    )
    with pytest.raises(SandboxDenied, match="Class 3"):
        run_in_sandbox(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="fake",
            adapter_version="1.0",
            request=req,
            engagements_root=env["engagements_root"],
            adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
            actor="test",
        )
    env["db"].close()
