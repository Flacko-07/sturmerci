# SPDX-License-Identifier: Apache-2.0
"""Batch A: scope_target separates the asset being assessed from the
network destination. WHOIS/Dig use this so the queried domain is the
asset checked against approved_assets, not the resolver/server hostname.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
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
from sentinel.runner.sandbox_runner import (
    SandboxDenied,
    SandboxRequest,
    run_in_sandbox,
    _current_scope_lock_hash,
    _current_egress_profile_id,
    _current_adapter_code_sha256,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


@contextlib.contextmanager
def _fake_ns(*a, **k):
    class _Ns:
        ns_name = "fake"
        run_id = "fake"
        veth_main = "fake-veth"
        veth_ns = "fake-veth-n"
        main_gateway_ip = "10.99.0.1"
        ns_ip = "10.99.0.2"
        base_dir = Path("/tmp/fake")

    yield _Ns()


class _FakeProc:
    def __init__(self):
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")
        self.returncode = 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass

    def communicate(self, timeout=None):
        return b"", b""


def _make_env(tmp_path, *, approved_asset_value="8.8.8.8"):
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name="scope-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id,
        raw_value=approved_asset_value,
        canonical_value=approved_asset_value,
        asset_type="hostname",
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
        approval_id="appr_scope",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=[approved_asset_value],
        allowed_ports=[53],
        allowed_protocols=["dns"],
        allowed_http_methods=["QUERY"],
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
        aggregate_byte_budget=1_000_000,
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


def _run(env, req):
    return run_in_sandbox(
        db=env["db"],
        engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="fake",
        adapter_version="1.0",
        request=req,
        engagements_root=env["engagements_root"],
        adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
        actor="op",
    )


def _mock_layers(monkeypatch):
    import sentinel.runner.sandbox_runner as sr

    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["8.8.8.8"])
    monkeypatch.setattr(sr, "run_namespace", _fake_ns)
    monkeypatch.setattr(sr.subprocess, "Popen", lambda *a, **k: _FakeProc())


def _req(**overrides):
    base = dict(
        hostname="8.8.8.8",
        port=53,
        protocol="dns",
        method="QUERY",
        path="/",
        argv=["/bin/true"],
        timeout_seconds=10,
        operation_profile="test/passthrough",
        profile_params={"argv": ["/bin/true"]},
        requires_target_connection=False,
    )
    base.update(overrides)
    return SandboxRequest(**base)


def test_scope_target_defaults_to_hostname(tmp_path, monkeypatch):
    env = _make_env(tmp_path, approved_asset_value="8.8.8.8")
    _mock_layers(monkeypatch)
    assert _run(env, _req()) is not None
    env["db"].close()


def test_scope_target_uses_scope_not_hostname(tmp_path, monkeypatch):
    env = _make_env(tmp_path, approved_asset_value="example.com")
    _mock_layers(monkeypatch)
    assert _run(env, _req(scope_target="example.com")) is not None
    env["db"].close()


def test_scope_target_mismatch_denied(tmp_path, monkeypatch):
    env = _make_env(tmp_path, approved_asset_value="example.com")
    _mock_layers(monkeypatch)
    with pytest.raises(SandboxDenied, match="scope_target"):
        _run(env, _req(scope_target="wrong.com"))
    env["db"].close()


def test_scope_target_empty_falls_back_to_hostname_denial(tmp_path, monkeypatch):
    env = _make_env(tmp_path, approved_asset_value="example.com")
    _mock_layers(monkeypatch)
    with pytest.raises(SandboxDenied, match="8\\.8\\.8\\.8"):
        _run(env, _req())
    env["db"].close()
