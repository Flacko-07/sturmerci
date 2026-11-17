# SPDX-License-Identifier: Apache-2.0
"""batch-4 P1: minimal env allowlist + watchdog policy/manifest drift.

All hermetic — `run_namespace` and `subprocess.Popen` are mocked.
Drift tests use a worker thread so the mutation lands *after* `_run`
has passed its initial checks and is inside the fake process's wait,
and *before* the watchdog's first 2-second poll.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.approval.store import (
    ApprovalRecord, ApprovalStore, target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.sandbox_runner import (
    SandboxRequest, SandboxRevoked, run_in_sandbox,
    _current_scope_lock_hash, _current_egress_profile_id,
    _current_adapter_code_sha256, _MINIMAL_SCANNER_ENV_KEYS,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


@contextlib.contextmanager
def _fake_namespace(*args, **kwargs):
    class _Ns:
        ns_name = "fake-ns-test"
        run_id = "faketest"
        ns_ip = "10.99.0.2"
        main_gateway_ip = "10.99.0.1"
    yield _Ns()


class _FakeProc:
    def __init__(self, duration: float = 4.0, returncode: int = 0):
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")
        self.returncode: int | None = None
        self._duration = duration
        self._final_rc = returncode

    def wait(self, timeout=None):
        time.sleep(self._duration)
        self.returncode = self._final_rc
        return self.returncode

    def kill(self):
        self.returncode = -9

    def communicate(self, timeout=None):
        return b"", b""


def _build_env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab", program_name="envtest", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id, raw_value="127.0.0.1",
        canonical_value="127.0.0.1", asset_type="ip",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    bin_sha = hashlib.sha256(Path("/bin/sh").read_bytes()).hexdigest()
    ManifestStore(db).register(ToolManifest(
        tool_name="envtest", version="1.0",
        executable_path="/bin/sh", executable_sha256=bin_sha,
        execution_class=2, network_access=True,
        allowed_profiles=("test/passthrough",),
        prohibited=(), limits={"max_runtime_seconds": 60},
        output_format="text",
    ), actor="test")

    adapter_path = Path("src/sentinel/runner/sandbox_runner.py")
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_envtest",
        engagement_id=eng.id, engagement_state_at_issue="active",
        policy_snapshot_hash="",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["127.0.0.1"],
        allowed_ports=[80], allowed_protocols=["http"],
        allowed_http_methods=["GET"], allowed_path_profile="default",
        operation_profile_id="test/passthrough",
        tool_name="envtest", tool_version="1.0",
        tool_executable_sha256=bin_sha,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
        manifest_hash=ManifestStore(db).get_by_tool_version(
            "envtest", "1.0").manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        normalized_arguments_hash="",
        request_rate_budget=5, aggregate_request_budget=50,
        aggregate_byte_budget=1_000_000, concurrency_budget=1,
        aggregate_runtime_budget=60, aggregate_model_token_budget=0,
        issued_by="op", issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(minutes=5)).isoformat(),
    )
    ApprovalStore(db).issue(appr)
    return {"db": db, "eng_id": eng.id,
            "approval_id": appr.approval_id,
            "engagements_root": tmp_path / "engagements"}


def _mk_request(**overrides):
    base = dict(
        hostname="127.0.0.1", port=80, protocol="http",
        method="GET", path="/",
        argv=["/bin/sh", "-c", "true"],
        timeout_seconds=20,
        operation_profile="test/passthrough",
        profile_params={"argv": ["/bin/sh", "-c", "true"]},
    )
    base.update(overrides)
    return SandboxRequest(**base)


def _run(env, req):
    return run_in_sandbox(
        db=env["db"], engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="envtest", adapter_version="1.0",
        request=req,
        engagements_root=env["engagements_root"],
        adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
        actor="op",
    )


# ====================================================================
# env_mode validation
# ====================================================================

def test_env_mode_invalid_refused_by_post_init():
    with pytest.raises(ValueError, match="env_mode"):
        SandboxRequest(
            hostname="127.0.0.1", port=80, protocol="http",
            method="GET", path="/",
            argv=["/bin/sh"], operation_profile="test/passthrough",
            profile_params={"argv": ["/bin/sh"]}, env_mode="nonsense",
        )


def test_minimal_env_default_constant():
    for required in ("PATH", "HOME", "TMPDIR", "LC_ALL", "LANG", "TZ"):
        assert required in _MINIMAL_SCANNER_ENV_KEYS, required
    for forbidden in ("AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY",
                      "GITHUB_TOKEN", "SSH_AUTH_SOCK", "BASH_ENV"):
        assert forbidden not in _MINIMAL_SCANNER_ENV_KEYS, forbidden


# ====================================================================
# env stripping
# ====================================================================

def test_minimal_env_strips_parent_vars(tmp_path, monkeypatch):
    env = _build_env(tmp_path)
    monkeypatch.setenv("SECRET_X", "please-do-not-leak")
    import sentinel.runner.sandbox_runner as sr
    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["1.1.1.1"])
    monkeypatch.setattr(sr, "run_namespace", _fake_namespace)
    captured: dict[str, str] = {}
    def _pop(argv, **kw):
        captured.update(kw.get("env") or {})
        return _FakeProc(duration=0.1)
    monkeypatch.setattr(sr.subprocess, "Popen", _pop)
    _run(env, _mk_request(env_mode="minimal"))
    assert "SECRET_X" not in captured
    assert "PATH" in captured
    env["db"].close()


def test_inherit_mode_keeps_parent_vars(tmp_path, monkeypatch):
    env = _build_env(tmp_path)
    monkeypatch.setenv("LEGACY_VAR", "yes")
    import sentinel.runner.sandbox_runner as sr
    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["1.1.1.1"])
    monkeypatch.setattr(sr, "run_namespace", _fake_namespace)
    captured: dict[str, str] = {}
    def _pop(argv, **kw):
        captured.update(kw.get("env") or {})
        return _FakeProc(duration=0.1)
    monkeypatch.setattr(sr.subprocess, "Popen", _pop)
    _run(env, _mk_request(env_mode="inherit"))
    assert captured.get("LEGACY_VAR") == "yes"
    env["db"].close()


def test_env_overrides_layer_on_top_of_minimal(tmp_path, monkeypatch):
    env = _build_env(tmp_path)
    import sentinel.runner.sandbox_runner as sr
    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["1.1.1.1"])
    monkeypatch.setattr(sr, "run_namespace", _fake_namespace)
    captured: dict[str, str] = {}
    def _pop(argv, **kw):
        captured.update(kw.get("env") or {})
        return _FakeProc(duration=0.1)
    monkeypatch.setattr(sr.subprocess, "Popen", _pop)
    _run(env, _mk_request(
        env_mode="minimal",
        env_overrides={"MY_CUSTOM_VAR": "custom-value"},
    ))
    assert captured.get("MY_CUSTOM_VAR") == "custom-value"
    env["db"].close()


# ====================================================================
# watchdog drift — worker-thread pattern
# ====================================================================

def test_watchdog_kills_on_policy_drift(tmp_path, monkeypatch):
    """_run in main thread; injector in worker thread with own DB.

    `_run` uses env["db"] (main-thread connection). The injector opens its
    own Database in the worker thread — sidesteps SQLite's
    check_same_thread restriction. `_run` blocks on the fake process's
    4-second wait; the injector commits at t=1.5s; watchdog poll at t=2s
    sees the new policy_snapshots row and revokes.
    """
    env = _build_env(tmp_path)
    import sentinel.runner.sandbox_runner as sr
    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["1.1.1.1"])
    monkeypatch.setattr(sr, "run_namespace", _fake_namespace)
    monkeypatch.setattr(
        sr.subprocess, "Popen", lambda *a, **k: _FakeProc(duration=4.0),
    )

    def _inject():
        time.sleep(1.5)
        db2 = Database(tmp_path / "sentinel.sqlite3")
        with db2.transaction() as conn:
            conn.execute(
                "INSERT INTO policy_snapshots "
                "(id, engagement_id, policy_hash, raw_text_path, "
                "created_at_utc) VALUES (?, ?, ?, ?, ?)",
                ("ps_drift", env["eng_id"], "policy_CHANGED",
                 "/tmp/p.txt", datetime.now(timezone.utc).isoformat()),
            )
        db2.close()

    t = threading.Thread(target=_inject, daemon=True)
    t.start()

    with pytest.raises(SandboxRevoked, match="policy_changed"):
        _run(env, _mk_request())

    t.join(timeout=5)
    env["db"].close()


def test_watchdog_kills_on_manifest_drift(tmp_path, monkeypatch):
    """Same pattern as policy drift: main-thread _run, worker-thread injector.

    Worker deletes + re-registers the manifest with a different binary
    hash. Watchdog compares current manifest_hash against the pre-run
    snapshot → SandboxRevoked.
    """
    env = _build_env(tmp_path)
    import sentinel.runner.sandbox_runner as sr
    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["1.1.1.1"])
    monkeypatch.setattr(sr, "run_namespace", _fake_namespace)
    monkeypatch.setattr(
        sr.subprocess, "Popen", lambda *a, **k: _FakeProc(duration=4.0),
    )

    def _inject():
        time.sleep(1.5)
        db2 = Database(tmp_path / "sentinel.sqlite3")
        db2.connection.execute(
            "DELETE FROM tool_manifests WHERE tool_name = 'envtest'"
        )
        db2.commit()
        ManifestStore(db2).register(ToolManifest(
            tool_name="envtest", version="1.0",
            executable_path="/bin/sh",
            executable_sha256="0" * 64,
            execution_class=2, network_access=True,
            allowed_profiles=("test/passthrough",),
            prohibited=(), limits={"max_runtime_seconds": 60},
            output_format="text",
        ), actor="test")
        db2.close()

    t = threading.Thread(target=_inject, daemon=True)
    t.start()

    with pytest.raises(SandboxRevoked, match="manifest_changed"):
        _run(env, _mk_request())

    t.join(timeout=5)
    env["db"].close()
