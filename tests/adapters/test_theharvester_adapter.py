# SPDX-License-Identifier: Apache-2.0
"""theHarvester adapter tests — hermetic."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.adapters.theharvester import (
    run_theharvester,
    parse_output,
    TheHarvesterAdapterError,
    ALLOWED_PROVIDERS,
    _validate_domain,
)
from sentinel.approval.store import (
    ApprovalRecord,
    ApprovalStore,
    target_asset_ids_hash,
    infrastructure_endpoints_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.sandbox_runner import (
    SandboxResult,
    _current_scope_lock_hash,
    _current_egress_profile_id,
    _current_adapter_code_sha256,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


def test_parse_output_extracts_hosts():
    text = json.dumps(
        {
            "hosts": [
                "api.example.com",
                "www.example.com:203.0.113.5",
                "mail.example.com:203.0.113.6,203.0.113.7",
                "api.example.com",  # duplicate
            ]
        }
    )
    findings = parse_output(text)
    assert [f.hostname for f in findings] == [
        "api.example.com",
        "www.example.com",
        "mail.example.com",
    ]


def test_parse_output_skips_invalid():
    text = json.dumps({"hosts": ["valid.example.com", "not_a_hostname", "", None]})
    findings = parse_output(text)
    assert [f.hostname for f in findings] == ["valid.example.com"]


def test_parse_output_empty():
    assert parse_output("") == []
    assert parse_output("{}") == []
    assert parse_output("not json") == []


def test_validate_domain_rejects_localhost():
    with pytest.raises(TheHarvesterAdapterError, match="refusing local"):
        _validate_domain("localhost")


def test_allowed_providers_constant():
    assert ALLOWED_PROVIDERS == {"crtsh", "otx", "rapiddns"}


def _build_env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name="harv-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id,
        raw_value="example.com",
        canonical_value="example.com",
        asset_type="hostname",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    bin_path = "/bin/true"
    h = hashlib.sha256(Path(bin_path).read_bytes()).hexdigest()
    providers = ["crtsh", "otx", "rapiddns"]
    ManifestStore(db).register(
        ToolManifest(
            tool_name="theHarvester",
            version="4.6.0",
            executable_path=bin_path,
            executable_sha256=h,
            execution_class=1,
            network_access=True,
            allowed_profiles=("passive_discovery",),
            prohibited=("-a", "-s", "-p"),
            limits={"max_runtime_seconds": 300},
            output_format="json",
            infrastructure_endpoints=tuple(providers),
        ),
        actor="test",
    )

    adapter_path = Path("src/sentinel/adapters/theharvester.py")
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_harv",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["example.com"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="",
        tool_name="theHarvester",
        tool_version="4.6.0",
        tool_executable_sha256=h,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
        manifest_hash=ManifestStore(db)
        .get_by_tool_version("theHarvester", "4.6.0")
        .manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        normalized_arguments_hash="",
        request_rate_budget=5,
        aggregate_request_budget=50,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=300,
        aggregate_model_token_budget=0,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(minutes=10)).isoformat(),
        approved_infrastructure_endpoints=providers,
        approved_infrastructure_endpoints_hash=infrastructure_endpoints_hash(providers),
    )
    ApprovalStore(db).issue(appr)
    return {
        "db": db,
        "eng_id": eng.id,
        "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
    }


def test_run_theharvester_rejects_bad_provider(tmp_path):
    env = _build_env(tmp_path)
    with pytest.raises(TheHarvesterAdapterError, match="allowlist"):
        run_theharvester(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_domain="example.com",
            engagements_root=env["engagements_root"],
            providers=("shodan",),
        )
    env["db"].close()


def test_run_theharvester_refuses_localhost(tmp_path):
    env = _build_env(tmp_path)
    with pytest.raises(TheHarvesterAdapterError, match="refusing local"):
        run_theharvester(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_domain="localhost",
            engagements_root=env["engagements_root"],
        )
    env["db"].close()


def test_run_theharvester_happy(tmp_path):
    env = _build_env(tmp_path)
    fake = SandboxResult(
        stdout="",
        stderr="",
        exit_code=0,
        duration_seconds=2.0,
        namespace_name="ns",
        resolved_ip="1.1.1.1",
        audit_event_seq=1,
        used_providers=("crtsh", "otx", "rapiddns"),
        resolved_ips=("1.1.1.1",),
    )
    import uuid as _uuid

    fixed = "testfixed1234567"
    run_dir = Path(f"/tmp/sentinel-harv-{fixed}")
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "harvester.json").write_text(
        json.dumps(
            {
                "hosts": ["api.example.com", "www.example.com"],
            }
        )
    )
    try:
        with patch("sentinel.adapters.theharvester.run_in_sandbox", return_value=fake):
            with patch.object(
                _uuid, "uuid4", return_value=type("U", (), {"hex": fixed})
            ):
                result = run_theharvester(
                    db=env["db"],
                    engagement_id=env["eng_id"],
                    approval_id=env["approval_id"],
                    target_domain="example.com",
                    engagements_root=env["engagements_root"],
                )
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
    assert result.findings_count == 2
    assert result.evidence.evidence_id.startswith("ev_")
    env["db"].close()
