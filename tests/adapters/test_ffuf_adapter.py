# SPDX-License-Identifier: Apache-2.0
"""ffuf adapter integration test — hermetic, mocks run_in_sandbox."""
from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.approval.store import (
    ApprovalRecord, ApprovalStore, target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.adapters.ffuf import (
    run_ffuf, parse_output, FfufAdapterError,
    _resolve_wordlist, _count_wordlist, DEFAULT_BLOCKED_PATHS,
)
from sentinel.runner.sandbox_runner import SandboxResult
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


FAKE_FFUF_OUTPUT = '''{
  "config": {"url": "https://app.test/FUZZ"},
  "results": [
    {"url": "https://app.test/admin", "status": 200, "length": 1234, "content-type": "text/html"},
    {"url": "https://app.test/api/v1", "status": 200, "length": 567, "content-type": "application/json"},
    {"url": "https://app.test/nonexistent", "status": 404, "length": 0, "content-type": "text/html"}
  ]
}'''


def _build_env(tmp_path, *, budget=500, rate=10):
    """Build a test env with fake ffuf manifest and wordlist."""
    # Write a tiny wordlist
    wl_dir = Path("config/wordlists")
    wl_dir.mkdir(parents=True, exist_ok=True)
    # Use existing common.txt

    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab", program_name="ffuf-test", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id, raw_value="app.test",
        canonical_value="app.test", asset_type="hostname",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    # Fake manifest
    fake_binary = "/bin/true"
    h = hashlib.sha256(Path(fake_binary).read_bytes()).hexdigest()
    ManifestStore(db).register(ToolManifest(
        tool_name="ffuf", version="2.1.0",
        executable_path=fake_binary, executable_sha256=h,
        execution_class=2, network_access=True,
        allowed_profiles=("dir_discovery",),
        prohibited=("post", "auth", "body", "proxy"),
        limits={"max_runtime_seconds": 60, "max_output_megabytes": 25},
        output_format="json",
    ), actor="test")

    from sentinel.runner.sandbox_runner import (
        _current_scope_lock_hash, _current_egress_profile_id,
        _current_adapter_code_sha256,
    )
    adapter_path = Path("src/sentinel/adapters/ffuf.py")
    scope = _current_scope_lock_hash(db, eng.id, "")
    egress = _current_egress_profile_id()
    adapter_hash = _current_adapter_code_sha256(adapter_path)

    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_ffuf",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="p",
        scope_lock_hash=scope,
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["app.test"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="dir_discovery",
        tool_name="ffuf", tool_version="2.1.0",
        tool_executable_sha256=h,
        adapter_code_sha256=adapter_hash,
        manifest_hash=ManifestStore(db).get_by_tool_version("ffuf", "2.1.0").manifest_hash,
        egress_profile_id=egress,
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
    return {"db": db, "eng_id": eng.id, "approval_id": appr.approval_id,
            "engagements_root": tmp_path / "engagements"}


def test_parse_output():
    findings = parse_output(FAKE_FFUF_OUTPUT)
    assert len(findings) == 3
    assert findings[0].path == "/admin"
    assert findings[0].status == 200


def test_parse_skips_malformed():
    text = '{"results": [{"url": "https://x/admin", "status": 200}, {"url": "bad"}]}'
    findings = parse_output(text)
    assert len(findings) == 1  # only the valid entry


def test_resolve_wordlist_ok():
    p = _resolve_wordlist("common.txt")
    assert p.is_file()


def test_wordlist_directory_override(monkeypatch, tmp_path):
    from sentinel.adapters.ffuf import _wordlist_dir

    monkeypatch.setenv("SENTINEL_WORDLIST_DIR", str(tmp_path))
    assert _wordlist_dir() == tmp_path.resolve()


def test_resolve_wordlist_refuses_traversal():
    with pytest.raises(FfufAdapterError, match="escapes"):
        _resolve_wordlist("../../etc/passwd")


def test_count_wordlist():
    n = _count_wordlist(_resolve_wordlist("common.txt"))
    assert n >= 50


def test_blocked_paths_constant():
    assert "/login" in DEFAULT_BLOCKED_PATHS
    assert "/auth" in DEFAULT_BLOCKED_PATHS


def test_run_ffuf_mocked_happy_path(tmp_path):
    env = _build_env(tmp_path, budget=500)
    fake_sandbox = SandboxResult(
        stdout=FAKE_FFUF_OUTPUT, stderr="", exit_code=0,
        duration_seconds=0.5, namespace_name="sentinel-run-test",
        resolved_ip="198.51.100.5", audit_event_seq=1,
        used_providers=(), resolved_ips=("198.51.100.5",),
    )
    with patch("sentinel.adapters.ffuf.run_in_sandbox",
               return_value=fake_sandbox):
        result = run_ffuf(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_hostname="app.test", port=443, scheme="https",
            wordlist_name="common.txt",
            engagements_root=env["engagements_root"],
        )
    # 3 results total; 0 blocked (none of them are auth paths)
    assert result.findings_count == 3
    assert result.evidence.evidence_id.startswith("ev_")
    env["db"].close()


def test_run_ffuf_budget_too_small(tmp_path):
    """Approval budget < wordlist_size * 1.1 must refuse."""
    env = _build_env(tmp_path, budget=5)  # way too small for common.txt
    with pytest.raises(FfufAdapterError, match="aggregate_request_budget"):
        run_ffuf(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_hostname="app.test", port=443, scheme="https",
            wordlist_name="common.txt",
            engagements_root=env["engagements_root"],
        )
    env["db"].close()
