# SPDX-License-Identifier: Apache-2.0
"""ZAP adapter tests — hermetic, mocks run_in_sandbox."""
from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.adapters.zap import (
    run_zap_baseline, parse_report, ZapAdapterError,
)
from sentinel.approval.store import (
    ApprovalRecord, ApprovalStore, target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.sandbox_runner import (
    SandboxResult, _current_scope_lock_hash, _current_egress_profile_id,
    _current_adapter_code_sha256,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


FAKE_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<OWASPZAPReport>
<site name="http://app.test" host="app.test" port="80" ssl="false">
<alerts>
<alertitem>
<pluginid>10020</pluginid>
<alert>Missing Anti-clickjacking Header</alert>
<name>X-Frame-Options Header Not Set</name>
<riskcode>2</riskcode>
<confidence>3</confidence>
<instances>
<instance><uri>http://app.test/</uri><method>GET</method></instance>
<instance><uri>http://app.test/login</uri><method>GET</method></instance>
</instances>
<cweid>1021</cweid>
</alertitem>
<alertitem>
<pluginid>10000</pluginid>
<alert>Server Leaks Version</alert>
<name>Server Leaks Version Information</name>
<riskcode>1</riskcode>
<confidence>3</confidence>
<instances>
<instance><uri>http://app.test/</uri><method>GET</method></instance>
</instances>
<cweid>200</cweid>
</alertitem>
</alerts>
</site>
</OWASPZAPReport>
'''


def test_parse_report_extracts_findings():
    findings = parse_report(FAKE_XML)
    assert len(findings) == 2
    xfo = findings[0]
    assert xfo.plugin_id == "10020"
    assert "X-Frame-Options" in xfo.name
    assert xfo.risk == "medium"
    assert xfo.confidence == "high"
    assert xfo.instance_count == 2
    assert xfo.url == "http://app.test/"
    assert xfo.cwe_id == "1021"


def test_parse_report_empty():
    assert parse_report("") == []
    assert parse_report("not xml") == []
    assert parse_report("<OWASPZAPReport><no-site/></OWASPZAPReport>") == []


def test_parse_report_risk_codes():
    xml = '''<OWASPZAPReport><site><alerts>
    <alertitem><pluginid>1</pluginid><name>H</name><riskcode>3</riskcode><confidence>3</confidence><instances/></alertitem>
    <alertitem><pluginid>2</pluginid><name>M</name><riskcode>2</riskcode><confidence>2</confidence><instances/></alertitem>
    <alertitem><pluginid>3</pluginid><name>L</name><riskcode>1</riskcode><confidence>1</confidence><instances/></alertitem>
    <alertitem><pluginid>4</pluginid><name>I</name><riskcode>0</riskcode><confidence>0</confidence><instances/></alertitem>
    </alerts></site></OWASPZAPReport>'''
    risks = [f.risk for f in parse_report(xml)]
    assert risks == ["high", "medium", "low", "info"]


def _build_env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab", program_name="zap-test", policy_url=None,
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

    bin_path = "/bin/true"
    h = hashlib.sha256(Path(bin_path).read_bytes()).hexdigest()
    from sentinel.adapters.zap import ZAP_VERSION
    ManifestStore(db).register(ToolManifest(
        tool_name="zap", version=ZAP_VERSION,
        executable_path=bin_path, executable_sha256=h,
        execution_class=2, network_access=True,
        allowed_profiles=("baseline_scan",),
        prohibited=("-a", "-j"), limits={"max_runtime_seconds": 900},
        output_format="xml",
    ), actor="test")

    adapter_path = Path("src/sentinel/adapters/zap.py")
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_zap",
        engagement_id=eng.id, engagement_state_at_issue="active",
        policy_snapshot_hash="",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["app.test"],
        allowed_ports=[443], allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="",
        tool_name="zap", tool_version=ZAP_VERSION,
        tool_executable_sha256=h,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
        manifest_hash=ManifestStore(db).get_by_tool_version(
            "zap", ZAP_VERSION).manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        normalized_arguments_hash="",
        request_rate_budget=10, aggregate_request_budget=200,
        aggregate_byte_budget=10_000_000, concurrency_budget=1,
        aggregate_runtime_budget=900, aggregate_model_token_budget=0,
        issued_by="op", issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(minutes=10)).isoformat(),
    )
    ApprovalStore(db).issue(appr)
    return {
        "db": db, "eng_id": eng.id, "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
    }


def test_run_zap_happy(tmp_path):
    env = _build_env(tmp_path)
    fake = SandboxResult(
        stdout="", stderr="", exit_code=0,
        duration_seconds=5.0, namespace_name="ns",
        resolved_ip="1.1.1.1", audit_event_seq=1,
        used_providers=(), resolved_ips=("1.1.1.1",),
    )
    import uuid as _uuid
    fixed = "testfixed1234567"
    run_dir = Path(f"/tmp/sentinel-zap-{fixed}")
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.xml").write_text(FAKE_XML)
    try:
        with patch("sentinel.adapters.zap.run_in_sandbox", return_value=fake):
            with patch.object(_uuid, "uuid4",
                              return_value=type("U", (), {"hex": fixed})):
                result = run_zap_baseline(
                    db=env["db"], engagement_id=env["eng_id"],
                    approval_id=env["approval_id"],
                    target_hostname="app.test", port=443, scheme="https",
                    engagements_root=env["engagements_root"],
                )
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
    assert result.findings_count == 2
    assert result.evidence.evidence_id.startswith("ev_")
    env["db"].close()


def test_run_zap_revoked_approval_refused(tmp_path):
    env = _build_env(tmp_path)
    ApprovalStore(env["db"]).revoke(env["approval_id"])
    with pytest.raises(ZapAdapterError, match="revoked"):
        run_zap_baseline(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_hostname="app.test", port=443, scheme="https",
            engagements_root=env["engagements_root"],
        )
    env["db"].close()
