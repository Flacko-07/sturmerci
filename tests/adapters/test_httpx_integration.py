# SPDX-License-Identifier: Apache-2.0
"""End-to-end httpx adapter test (M7.1). Fake httpx binary through sandbox."""

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
from sentinel.adapters.httpx import run_httpx, HTTPX_VERSION
from sentinel.engagement.store import EngagementStore
from sentinel.runner import sandbox_runner as _sr
from sentinel.runner.sandbox_runner import SandboxDenied
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="integration requires root (namespace creation)",
)


FAKE_JSONL = (
    '{"port":"443","url":"https://probe.test:443","input":"probe.test",'
    '"title":"Test Site","scheme":"https","webserver":"nginx",'
    '"tech":["nginx"],"status_code":200,'
    '"tls":{"subject_cn":"probe.test","issuer_cn":"Self","dns_names":["probe.test"]}}\n'
)


def _make_fake_httpx(tmp_path: Path) -> tuple[Path, str]:
    """Create fake httpx under /tmp (world-traversable for nobody).

    Uses chr(10) for newlines to avoid shell/Python escaping corruption.
    """
    import tempfile

    bin_dir = Path(tempfile.mkdtemp(prefix="sentinel-test-bin-httpx-"))
    bin_dir.chmod(0o755)
    script = bin_dir / "fake_httpx"
    NL = chr(10)
    content = "#!/bin/sh" + NL + "cat <<'JSONL'" + NL + FAKE_JSONL + "JSONL" + NL
    script.write_text(content)
    script.chmod(0o755)
    first_line = script.read_text().split(NL, 1)[0]
    assert first_line == "#!/bin/sh", f"shebang corrupted: {first_line!r}"
    sha = hashlib.sha256(script.read_bytes()).hexdigest()
    return script, sha


def _build_env(tmp_path, *, path_profile="default"):
    binary, binary_sha = _make_fake_httpx(tmp_path)
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name="httpx-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    asset_store = AssetStore(db)
    cid = asset_store.add_candidate(
        engagement_id=eng.id,
        raw_value="probe.test",
        canonical_value="probe.test",
        asset_type="hostname",
        discovery_source="test",
    )
    asset_id = asset_store.promote_candidate(cid, approved_by="op")
    target_ids = [asset_id]
    target_hash = target_asset_ids_hash(target_ids)

    manifest_store = ManifestStore(db)
    m = ToolManifest(
        tool_name="httpx",
        version=HTTPX_VERSION,
        executable_path=str(binary.resolve()),
        executable_sha256=binary_sha,
        execution_class=2,
        network_access=True,
        allowed_profiles=("httpx/inventory",),
        prohibited=(
            "path_restricted",
            "follow_redirects",
            "arbitrary_headers",
            "non_get_methods",
            "request_body",
            "proxy",
        ),
        limits={"max_runtime_seconds": 60},
        output_format="jsonl",
        infrastructure_endpoints=(),
    )
    registered = manifest_store.register(m, actor="op")

    from sentinel.runner.sandbox_runner import (
        _current_scope_lock_hash,
        _current_egress_profile_id,
        _current_adapter_code_sha256,
    )

    adapter_file = (
        Path(__file__).parent.parent.parent
        / "src"
        / "sentinel"
        / "adapters"
        / "httpx.py"
    )
    current_scope = _current_scope_lock_hash(db, eng.id, "")
    current_egress = _current_egress_profile_id()
    current_adapter_hash = _current_adapter_code_sha256(adapter_file)

    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_httpx_test",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="policy_A",
        scope_lock_hash=current_scope,
        target_asset_ids=target_ids,
        target_asset_ids_hash=target_hash,
        canonical_hostnames=["probe.test"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET", "HEAD"],
        allowed_path_profile=path_profile,
        operation_profile_id="httpx/inventory",
        tool_name=m.tool_name,
        tool_version=m.version,
        tool_executable_sha256=binary_sha,
        adapter_code_sha256=current_adapter_hash,
        manifest_hash=registered.manifest_hash,
        egress_profile_id=current_egress,
        normalized_arguments_hash="",
        request_rate_budget=10,
        aggregate_request_budget=100,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=60,
        aggregate_model_token_budget=10_000,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
        approved_infrastructure_endpoints=[],
    )
    ApprovalStore(db).issue(appr)

    return {
        "db": db,
        "eng_id": eng.id,
        "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
    }


def _stub_resolver(monkeypatch):
    monkeypatch.setattr(
        _sr,
        "_resolve_hostname",
        lambda h: ["1.1.1.1"] if h == "probe.test" else [],
    )


def test_inventory_happy_path_writes_web_endpoint(tmp_path, monkeypatch):
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path)
    try:
        result = run_httpx(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_hostname="probe.test",
            port=443,
            scheme="https",
            method="GET",
            engagements_root=env["engagements_root"],
            actor="op",
            timeout_seconds=30,
        )
        assert result.endpoints_written == 1
        row = (
            env["db"]
            .connection.execute(
                "SELECT canonical_value, asset_type, discovery_source "
                "FROM candidate_assets "
                "WHERE engagement_id = ? AND review_state = 'pending' "
                "AND asset_type = 'web_endpoint'",
                (env["eng_id"],),
            )
            .fetchone()
        )
        assert row is not None
        assert row["canonical_value"] == "https://probe.test:443"
        assert row["discovery_source"] == "httpx:inventory"
    finally:
        env["db"].close()


def test_path_restricted_approval_refused(tmp_path, monkeypatch):
    """Cross-check with M7.1: path_profile != 'default' blocks httpx."""
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, path_profile="/api/v1")
    try:
        with pytest.raises(SandboxDenied, match="path-restricted"):
            run_httpx(
                db=env["db"],
                engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                target_hostname="probe.test",
                port=443,
                scheme="https",
                method="GET",
                engagements_root=env["engagements_root"],
                actor="op",
                timeout_seconds=30,
            )
    finally:
        env["db"].close()


# --- M7-04: full inventory metadata persisted ---


def test_m7p04_inventory_metadata_persisted(tmp_path, monkeypatch):
    """HTTPX adapter writes status/tech/TLS to discovery_metadata_json."""
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path)
    try:
        result = run_httpx(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_hostname="probe.test",
            port=443,
            scheme="https",
            method="GET",
            engagements_root=env["engagements_root"],
            actor="op",
            timeout_seconds=30,
        )
        assert result.endpoints_written == 1
        row = (
            env["db"]
            .connection.execute(
                "SELECT discovery_metadata_json FROM candidate_assets "
                "WHERE engagement_id = ? AND asset_type = 'web_endpoint'",
                (env["eng_id"],),
            )
            .fetchone()
        )
        assert row is not None
        import json

        meta = json.loads(row["discovery_metadata_json"])
        assert meta["status_code"] == 200
        assert meta["title"] == "Test Site"
        assert meta["webserver"] == "nginx"
        assert "nginx" in meta["tech"]
        assert meta["tls_subject_cn"] == "probe.test"
        assert "probe.test" in meta["tls_dns_names"]
    finally:
        env["db"].close()
