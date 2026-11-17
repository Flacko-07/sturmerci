# SPDX-License-Identifier: Apache-2.0
"""nikto adapter test — hermetic, mocks run_in_sandbox."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import sentinel.runner.builtin_profiles  # noqa: F401
from sentinel.adapters.nikto import (
    run_nikto,
    parse_output,
    ALLOWED_TUNINGS,
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


FAKE_NIKTO_OUTPUT = """{
  "host": "app.test",
  "ip": "198.51.100.5",
  "port": 443,
  "banner": "nginx/1.24.0",
  "vulnerabilities": [
    {"id": "999957", "method": "GET", "url": "/",
     "msg": "X-Content-Type-Options header is not set", "references": ""},
    {"id": "000042", "method": "GET", "url": "/.git/HEAD",
     "msg": "Git repository exposed", "references": "OSVDB-842"}
  ]
}"""


def test_parse_output_happy():
    findings, banner = parse_output(FAKE_NIKTO_OUTPUT)
    assert len(findings) == 2
    assert banner == "nginx/1.24.0"
    assert findings[0].item_id == "999957"
    assert findings[1].url == "/.git/HEAD"


def test_parse_output_items_fallback():
    """Older/newer nikto versions may emit `items` instead of `vulnerabilities`."""
    text = '{"items": [{"id": "1", "url": "/", "msg": "test"}]}'
    findings, _ = parse_output(text)
    assert len(findings) == 1


def test_parse_output_skips_garbage():
    text = '{"vulnerabilities": [{"id": "1", "url": "/x", "msg": "ok"}, "bad", {"method": "GET"}]}'
    findings, _ = parse_output(text)
    # "bad" is not a dict -> skipped. {"method": "GET"} has no url/msg -> skipped.
    assert len(findings) == 1


def test_parse_output_malformed_json():
    findings, banner = parse_output("not json")
    assert findings == [] and banner == ""


def test_allowed_tunings_constant():
    assert ALLOWED_TUNINGS == "123"
    assert set(ALLOWED_TUNINGS) <= set("123")


def test_profile_builds_valid_argv():
    argv = build_argv_for_profile(
        profile_name="nikto/web_server_scan",
        executable_path="/usr/bin/nikto.pl",
        params={
            "hostname": "app.test",
            "port": 443,
            "scheme": "https",
            "tunings": "123",
            "pause_seconds": 0.1,
            "max_time_seconds": 300,
        },
    )
    assert "-ssl" in argv
    assert "-Tuning" in argv
    assert argv[argv.index("-Tuning") + 1] == "123"


def test_profile_refuses_tuning_4plus():
    with pytest.raises(Exception, match="tunings"):
        build_argv_for_profile(
            profile_name="nikto/web_server_scan",
            executable_path="/usr/bin/nikto.pl",
            params={
                "hostname": "app.test",
                "port": 443,
                "scheme": "https",
                "tunings": "1234",
                "pause_seconds": 0.1,
                "max_time_seconds": 300,
            },
        )


def _build_env(tmp_path, *, budget=2000, rate=10):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="nikto-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id,
        raw_value="app.test",
        canonical_value="app.test",
        asset_type="hostname",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    fake_binary = "/bin/true"
    h = hashlib.sha256(Path(fake_binary).read_bytes()).hexdigest()
    from sentinel.adapters.nikto import NIKTO_VERSION

    ManifestStore(db).register(
        ToolManifest(
            tool_name="nikto",
            version=NIKTO_VERSION,
            executable_path=fake_binary,
            executable_sha256=h,
            execution_class=2,
            network_access=True,
            allowed_profiles=("web_server_scan",),
            prohibited=("-evasion", "-useproxy"),
            limits={"max_runtime_seconds": 60, "max_output_megabytes": 25},
            output_format="json",
        ),
        actor="test",
    )

    from sentinel.runner.sandbox_runner import (
        _current_scope_lock_hash,
        _current_egress_profile_id,
        _current_adapter_code_sha256,
    )

    adapter_path = Path("src/sentinel/adapters/nikto.py")
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_nikto",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="p",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["app.test"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="web_server_scan",
        tool_name="nikto",
        tool_version=NIKTO_VERSION,
        tool_executable_sha256=h,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
        manifest_hash=ManifestStore(db)
        .get_by_tool_version("nikto", NIKTO_VERSION)
        .manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        normalized_arguments_hash="",
        request_rate_budget=rate,
        aggregate_request_budget=budget,
        aggregate_byte_budget=10_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=600,
        aggregate_model_token_budget=100_000,
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


def test_run_nikto_happy(tmp_path):
    env = _build_env(tmp_path)
    fake = SandboxResult(
        stdout=FAKE_NIKTO_OUTPUT,
        stderr="",
        exit_code=0,
        duration_seconds=1.0,
        namespace_name="ns-test",
        resolved_ip="198.51.100.5",
        audit_event_seq=1,
        used_providers=(),
        resolved_ips=("198.51.100.5",),
    )
    with patch("sentinel.adapters.nikto.run_in_sandbox", return_value=fake):
        result = run_nikto(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_hostname="app.test",
            port=443,
            scheme="https",
            engagements_root=env["engagements_root"],
        )
    assert result.findings_count == 2
    assert result.banner == "nginx/1.24.0"
    assert result.evidence.evidence_id.startswith("ev_")
    env["db"].close()
