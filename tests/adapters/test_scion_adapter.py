# SPDX-License-Identifier: Apache-2.0
"""scion adapter test — hermetic, mocks run_in_sandbox."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import sentinel.runner.builtin_profiles  # noqa: F401
from sentinel.adapters.scion import (
    run_scion,
    parse_output,
    ScionAdapterError,
    _validate_domain,
)
from sentinel.approval.store import (
    ApprovalRecord,
    ApprovalStore,
    target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.profiles import build_argv_for_profile
from sentinel.runner.sandbox_runner import SandboxResult
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


FAKE_OUTPUT = """api.example.com
www.example.com
mail.example.com
api.example.com
not_a_hostname
"""


def test_parse_output_dedupes():
    findings = parse_output(FAKE_OUTPUT)
    assert [f.hostname for f in findings] == [
        "api.example.com",
        "www.example.com",
        "mail.example.com",
    ]


def test_parse_output_empty():
    assert parse_output("") == []


def test_validate_domain_rejects_localhost():
    with pytest.raises(ScionAdapterError, match="refusing local"):
        _validate_domain("localhost")


def test_profile_builds_valid_argv():
    argv = build_argv_for_profile(
        profile_name="scion/passive_discovery",
        executable_path="/usr/local/bin/scion",
        params={"domain": "example.com"},
    )
    assert "--subs-only" in argv
    assert "--silent" in argv
    assert "example.com" in argv


def _build_env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="scion-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id,
        raw_value="example.com",
        canonical_value="example.com",
        asset_type="hostname",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    fake_binary = "/bin/true"
    h = hashlib.sha256(Path(fake_binary).read_bytes()).hexdigest()
    from sentinel.adapters.scion import SCION_VERSION

    ManifestStore(db).register(
        ToolManifest(
            tool_name="scion",
            version=SCION_VERSION,
            executable_path=fake_binary,
            executable_sha256=h,
            execution_class=1,
            network_access=True,
            allowed_profiles=("passive_discovery",),
            prohibited=(
                "--verify",
                "--output",
                "--out-file",
                "--compare",
                "--scope-file",
            ),
            limits={"max_runtime_seconds": 300, "max_output_megabytes": 10},
            output_format="text",
            infrastructure_endpoints=(),
        ),
        actor="test",
    )

    from sentinel.runner.sandbox_runner import (
        _current_scope_lock_hash,
        _current_egress_profile_id,
        _current_adapter_code_sha256,
    )

    adapter_path = Path("src/sentinel/adapters/scion.py")
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_scion",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="p",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["example.com"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="passive_discovery",
        tool_name="scion",
        tool_version=SCION_VERSION,
        tool_executable_sha256=h,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
        manifest_hash=ManifestStore(db)
        .get_by_tool_version("scion", SCION_VERSION)
        .manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        normalized_arguments_hash="",
        request_rate_budget=10,
        aggregate_request_budget=100,
        aggregate_byte_budget=10_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=300,
        aggregate_model_token_budget=50_000,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
    )
    ApprovalStore(db).issue(appr)
    return {
        "db": db,
        "eng_id": eng.id,
        "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
    }


def test_run_scion_happy(tmp_path):
    env = _build_env(tmp_path)
    fake = SandboxResult(
        stdout=FAKE_OUTPUT,
        stderr="",
        exit_code=0,
        duration_seconds=1.0,
        namespace_name="ns",
        resolved_ip="203.0.113.10",
        audit_event_seq=1,
        used_providers=(),
        resolved_ips=("203.0.113.10",),
    )
    with patch("sentinel.adapters.scion.run_in_sandbox", return_value=fake):
        result = run_scion(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_domain="example.com",
            engagements_root=env["engagements_root"],
        )
    assert result.findings_count == 3
    assert result.evidence.evidence_id.startswith("ev_")
    env["db"].close()
