# SPDX-License-Identifier: Apache-2.0
"""batch-6: normalized_arguments_hash + operation_profile_id binding.

Every test mocks `run_namespace` with a fake, and mocks subprocess.Popen
where relevant — so all denials fire as SandboxDenied *before* namespace
setup, and the pass-through cases complete without root.

Reviewer's P0.2: "The approval fields `operation_profile_id` and
`normalized_arguments_hash` are also not compared against the actual
request."
"""
from __future__ import annotations

import contextlib
import hashlib
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.approval.store import (
    ApprovalRecord, ApprovalStore, target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.profiles import params_hash
from sentinel.runner.sandbox_runner import (
    SandboxDenied, SandboxRequest, run_in_sandbox,
    _current_scope_lock_hash, _current_egress_profile_id,
    _current_adapter_code_sha256,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest
import sentinel.runner.builtin_profiles  # noqa: F401


@contextlib.contextmanager
def _fake_namespace(*a, **k):
    class _Ns:
        ns_name = "fake-ns"
        run_id = "faketest"
        ns_ip = "10.99.0.2"
        main_gateway_ip = "10.99.0.1"
    yield _Ns()


class _FakeProc:
    def __init__(self, duration=0.1, returncode=0):
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")
        self.returncode = None
        self._duration = duration
        self._final_rc = returncode
    def wait(self, timeout=None):
        import time; time.sleep(self._duration)
        self.returncode = self._final_rc
        return self.returncode
    def kill(self):
        self.returncode = -9
    def communicate(self, timeout=None):
        return b"", b""


def _make_env(tmp_path, *, bound_params=None, bound_profile="test/echo"):
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab", program_name="binding-test", policy_url=None,
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
        tool_name="binding", version="1.0",
        executable_path="/bin/sh", executable_sha256=bin_sha,
        execution_class=2, network_access=True,
        allowed_profiles=("test/echo", "test/exploit"),
        prohibited=(), limits={"max_runtime_seconds": 60},
        output_format="text",
    ), actor="test")

    adapter_path = Path("src/sentinel/runner/sandbox_runner.py")
    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_binding",
        engagement_id=eng.id, engagement_state_at_issue="active",
        policy_snapshot_hash="",
        scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
        target_asset_ids=[aid],
        target_asset_ids_hash=target_asset_ids_hash([aid]),
        canonical_hostnames=["127.0.0.1"],
        allowed_ports=[80], allowed_protocols=["http"],
        allowed_http_methods=["GET"], allowed_path_profile="default",
        operation_profile_id=bound_profile,
        tool_name="binding", tool_version="1.0",
        tool_executable_sha256=bin_sha,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
        manifest_hash=ManifestStore(db).get_by_tool_version(
            "binding", "1.0").manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        normalized_arguments_hash=(
            params_hash(bound_params) if bound_params is not None else ""
        ),
        profile_params=bound_params or {},
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


def _req(profile="test/echo", params=None):
    params = {"msg": "hello"} if params is None else params
    message = params.get("msg", "exploit")
    return SandboxRequest(
        hostname="127.0.0.1", port=80, protocol="http",
        method="GET", path="/",
        argv=["/bin/sh", message],
        timeout_seconds=10,
        operation_profile=profile,
        profile_params=params,
    )


def _run(env, req):
    return run_in_sandbox(
        db=env["db"], engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="binding", adapter_version="1.0",
        request=req,
        engagements_root=env["engagements_root"],
        adapter_code_path=Path("src/sentinel/runner/sandbox_runner.py"),
        actor="op",
    )


def _mock_runner_layers(monkeypatch):
    import sentinel.runner.sandbox_runner as sr
    monkeypatch.setattr(sr, "_resolve_hostname", lambda h: ["1.1.1.1"])
    monkeypatch.setattr(sr, "run_namespace", _fake_namespace)
    monkeypatch.setattr(sr.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(duration=0.1))


# ====================================================================
# 6A — normalized_arguments_hash
# ====================================================================

def test_params_hash_is_deterministic():
    a = params_hash({"wordlist": "common.txt", "rate": "10"})
    b = params_hash({"rate": "10", "wordlist": "common.txt"})
    assert a == b
    c = params_hash({"wordlist": "other.txt", "rate": "10"})
    assert a != c


def test_fixture_sets_hash_correctly(tmp_path):
    """Sanity: fixture writes and reads back normalized_arguments_hash."""
    bound = {"msg": "hello"}
    env = _make_env(tmp_path, bound_params=bound)
    appr = ApprovalStore(env["db"]).get(env["approval_id"])
    assert appr is not None
    assert appr.normalized_arguments_hash == params_hash(bound), (
        f"fixture roundtrip failed: got {appr.normalized_arguments_hash!r}, "
        f"expected {params_hash(bound)!r}"
    )
    assert appr.profile_params == bound, (
        f"fixture profile_params roundtrip failed: got "
        f"{appr.profile_params!r}, expected {bound!r}"
    )
    env["db"].close()


def test_bound_params_mismatch_denied(tmp_path, monkeypatch):
    """Request params differ from bound → SandboxDenied before namespace."""
    bound = {"msg": "hello"}
    env = _make_env(tmp_path, bound_params=bound)
    _mock_runner_layers(monkeypatch)

    req = _req(params={"msg": "different"})
    with pytest.raises(SandboxDenied, match="do not match the params bound"):
        _run(env, req)
    env["db"].close()


def test_bound_params_match_passes(tmp_path, monkeypatch):
    """Request params match bound → passes binding; completes (fake ns)."""
    bound = {"msg": "hello"}
    env = _make_env(tmp_path, bound_params=bound)
    _mock_runner_layers(monkeypatch)

    req = _req(params={"msg": "hello"})
    result = _run(env, req)  # must not raise
    assert result is not None
    env["db"].close()


def test_no_bound_params_skips_check(tmp_path, monkeypatch):
    """Empty normalized_arguments_hash → no param binding, request proceeds."""
    env = _make_env(tmp_path, bound_params=None)
    _mock_runner_layers(monkeypatch)

    req = _req(params={"msg": "anything"})
    result = _run(env, req)  # must not raise
    assert result is not None
    env["db"].close()


def test_class3_profile_rejects_missing_empty_param_binding(tmp_path, monkeypatch):
    env = _make_env(tmp_path, bound_params=None, bound_profile="test/exploit")
    _mock_runner_layers(monkeypatch)
    with pytest.raises(SandboxDenied, match="requires its parameters"):
        _run(env, _req(profile="test/exploit", params={}))
    env["db"].close()


def test_class3_empty_param_set_is_explicitly_bound(tmp_path, monkeypatch):
    env = _make_env(tmp_path, bound_params={}, bound_profile="test/exploit")
    _mock_runner_layers(monkeypatch)
    # The binding succeeds; the independent Class 3 approval gate still
    # rejects because this fixture does not carry intrusive authorization.
    with pytest.raises(SandboxDenied, match="Class 3"):
        _run(env, _req(profile="test/exploit", params={}))
    env["db"].close()


# ====================================================================
# 6B — operation_profile_id binding
# ====================================================================

def test_profile_mismatch_denied(tmp_path, monkeypatch):
    """Approval bound to test/echo; request uses test/exploit → denied."""
    env = _make_env(tmp_path, bound_profile="test/echo")
    _mock_runner_layers(monkeypatch)

    req = _req(profile="test/exploit", params={"msg": "hello"})
    with pytest.raises(SandboxDenied, match="operation_profile"):
        _run(env, req)
    env["db"].close()


def test_profile_match_passes(tmp_path, monkeypatch):
    """Approval bound to test/echo; request uses test/echo → passes."""
    env = _make_env(tmp_path, bound_profile="test/echo")
    _mock_runner_layers(monkeypatch)

    req = _req(profile="test/echo", params={"msg": "hello"})
    result = _run(env, req)  # must not raise
    assert result is not None
    env["db"].close()
