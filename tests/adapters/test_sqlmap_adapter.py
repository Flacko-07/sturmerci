# SPDX-License-Identifier: Apache-2.0
"""sqlmap adapter test — hermetic, mocks run_in_sandbox."""
from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import sentinel.runner.builtin_profiles  # noqa: F401
from sentinel.adapters.sqlmap import (
    run_sqlmap, parse_log, is_clean_run, SqlmapAdapterError,
)
from sentinel.approval.store import (
    ApprovalRecord, ApprovalStore, target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.profiles import build_argv_for_profile
from sentinel.runner.sandbox_runner import SandboxResult
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


INJECTABLE_LOG = """\
[12:00:00] [INFO] testing connection to the target URL
[12:00:02] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[12:00:03] [INFO] POST parameter 'user' appears to be 'Boolean-based blind - Parameter replace' injectable
"""

CLEAN_LOG = """\
[12:00:00] [INFO] testing connection to the target URL
[12:00:02] [CRITICAL] all tested parameters do not appear to be injectable.
"""


def test_parse_log_extracts_injectable():
    findings = parse_log(INJECTABLE_LOG)
    assert len(findings) == 2
    assert findings[0].method == "GET"
    assert findings[0].parameter == "id"
    assert "boolean" in findings[0].technique.lower()
    assert findings[1].method == "POST"
    assert findings[1].parameter == "user"


def test_parse_log_clean_returns_empty():
    assert parse_log(CLEAN_LOG) == []


def test_parse_log_empty():
    assert parse_log("") == []


def test_is_clean_run():
    assert is_clean_run(CLEAN_LOG) is True
    assert is_clean_run(INJECTABLE_LOG) is False
    assert is_clean_run("") is False


def test_profile_builds_get_argv():
    argv = build_argv_for_profile(
        profile_name="sqlmap/detect",
        executable_path="/usr/bin/sqlmap",
        params={"hostname": "127.0.0.1", "port": 18080, "scheme": "http",
                "path": "/", "query": "id=1", "data": None,
                "output_dir": "/tmp/sentinel-sqlmap-abc123",
                "delay_seconds": 1, "technique": "B"},
    )
    assert "-u" in argv
    assert argv[argv.index("-u") + 1] == "http://127.0.0.1:18080/?id=1"
    assert "--batch" in argv
    assert "--flush-session" in argv
    assert "--level=1" in argv and "--risk=1" in argv
    assert "--technique=B" in argv
    assert not any(a.startswith("--data=") for a in argv)


def test_profile_builds_post_argv():
    argv = build_argv_for_profile(
        profile_name="sqlmap/detect",
        executable_path="/usr/bin/sqlmap",
        params={"hostname": "127.0.0.1", "port": 18080, "scheme": "http",
                "path": "/login", "query": "", "data": "user=admin&pass=x",
                "output_dir": "/tmp/sentinel-sqlmap-abc123",
                "delay_seconds": 1, "technique": "B"},
    )
    assert "--data=user=admin&pass=x" in argv


def test_profile_refuses_union_technique():
    with pytest.raises(Exception, match="technique"):
        build_argv_for_profile(
            profile_name="sqlmap/detect",
            executable_path="/usr/bin/sqlmap",
            params={"hostname": "127.0.0.1", "port": 18080, "scheme": "http",
                    "path": "/", "query": "id=1", "data": None,
                    "output_dir": "/tmp/sentinel-sqlmap-abc123",
                    "delay_seconds": 1, "technique": "U"},
        )


def test_profile_refuses_outside_tmp_output():
    with pytest.raises(Exception, match="output_dir"):
        build_argv_for_profile(
            profile_name="sqlmap/detect",
            executable_path="/usr/bin/sqlmap",
            params={"hostname": "127.0.0.1", "port": 18080, "scheme": "http",
                    "path": "/", "query": "id=1", "data": None,
                    "output_dir": "/etc/passwd",
                    "delay_seconds": 1, "technique": "B"},
        )


def _build_env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab", program_name="sqlmap-test", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id, raw_value="127.0.0.1",
        canonical_value="127.0.0.1", asset_type="ip",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    fake_binary = "/bin/true"
    h = hashlib.sha256(Path(fake_binary).read_bytes()).hexdigest()
    from sentinel.adapters.sqlmap import SQLMAP_VERSION
    ManifestStore(db).register(ToolManifest(
        tool_name="sqlmap", version=SQLMAP_VERSION,
        executable_path=fake_binary, executable_sha256=h,
        execution_class=3, network_access=True,
        allowed_profiles=("detect",),
        prohibited=("--dump", "--os-shell"),
        limits={"max_runtime_seconds": 300, "max_output_megabytes": 5},
        output_format="text",
    ), actor="test")

    from sentinel.runner.sandbox_runner import (
        _current_scope_lock_hash, _current_egress_profile_id,
        _current_adapter_code_sha256,
    )
    adapter_path = Path("src/sentinel/adapters/sqlmap.py")
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_sqlmap_t",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="p",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["127.0.0.1"],
        allowed_ports=[18080],
        allowed_protocols=["http"],
        allowed_http_methods=["GET", "POST"],
        allowed_path_profile="default",
        operation_profile_id="detect",
        tool_name="sqlmap", tool_version=SQLMAP_VERSION,
        tool_executable_sha256=h,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
        manifest_hash=ManifestStore(db).get_by_tool_version(
            "sqlmap", SQLMAP_VERSION
        ).manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        normalized_arguments_hash="",
        request_rate_budget=1,
        aggregate_request_budget=50,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=300,
        aggregate_model_token_budget=0,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
        intrusive_authorized=True,
        lab_environment=True,
    )
    ApprovalStore(db).issue(appr)
    return {"db": db, "eng_id": eng.id, "approval_id": appr.approval_id,
            "engagements_root": tmp_path / "engagements"}


def test_run_sqlmap_parses_injectable(tmp_path):
    env = _build_env(tmp_path)
    fake = SandboxResult(
        stdout="", stderr="", exit_code=0,
        duration_seconds=1.0, namespace_name="ns",
        resolved_ip="127.0.0.1", audit_event_seq=1,
        used_providers=(), resolved_ips=("127.0.0.1",),
    )
    import uuid as _uuid
    fixed = "testfixedabc123"
    out_dir = Path(f"/tmp/sentinel-sqlmap-{fixed}")
    (out_dir / "127.0.0.1").mkdir(parents=True, exist_ok=True)
    (out_dir / "127.0.0.1" / "log").write_text(INJECTABLE_LOG)
    try:
        with patch("sentinel.adapters.sqlmap.run_in_sandbox", return_value=fake):
            with patch.object(_uuid, "uuid4",
                              return_value=type("U", (), {"hex": fixed})):
                result = run_sqlmap(
                    db=env["db"], engagement_id=env["eng_id"],
                    approval_id=env["approval_id"],
                    target_hostname="127.0.0.1", port=18080, scheme="http",
                    engagements_root=env["engagements_root"],
                    query="id=1",
                )
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
    assert result.findings_count == 2
    assert result.evidence.evidence_id.startswith("ev_")
    env["db"].close()
