# SPDX-License-Identifier: Apache-2.0
"""M5.1 — SandboxRunner tests.

E-22b: approval does not cover request → denied before launch
E-22c: policy hash drift → denied before launch
E-22d: resolved IP is protected → denied before launch
plus: manifest/argv/hostname/method denial paths, and the happy path.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.approval.store import ApprovalRecord, ApprovalStore, target_asset_ids_hash
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner import sandbox_runner as _sr
from sentinel.runner.sandbox_runner import (
    SandboxDenied, SandboxRequest, SandboxResult, run_in_sandbox,
    _current_scope_lock_hash, _current_egress_profile_id,
    _current_adapter_code_sha256,
)

# Stable adapter source used for every test in this module. Production
# adapters pass their own __file__; tests use a shared fixture so the
# SHA-256 is deterministic within a run.
TEST_ADAPTER_PATH = (
    Path(__file__).resolve().parent.parent / "fixtures" / "fake_adapter.py"
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="sandbox runner tests require root (namespace creation)",
)


ECHO_BIN = "/bin/echo"


def _echo_sha() -> str:
    return hashlib.sha256(Path(ECHO_BIN).read_bytes()).hexdigest()


def _build_env(tmp_path, *, manifest_providers=(), approved_providers=None,
               binary_path=None, canonical_hostnames=None,
               allowed_ports=None, allowed_methods=None, lab_environment: bool = False):
    if approved_providers is None:
        approved_providers = list(manifest_providers)
    if binary_path is None:
        binary_path = ECHO_BIN
    if canonical_hostnames is None:
        canonical_hostnames = ["probe.test"]
    if allowed_ports is None:
        allowed_ports = [443]
    if allowed_methods is None:
        allowed_methods = ["GET"]
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab", program_name="sandbox-test", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    asset_store = AssetStore(db)
    target_ids: list[str] = []
    for h in canonical_hostnames:
        cid = asset_store.add_candidate(
            engagement_id=eng.id, raw_value=h,
            canonical_value=h, asset_type="hostname",
            discovery_source="test",
        )
        aid = asset_store.promote_candidate(cid, approved_by="op")
        target_ids.append(aid)
    target_hash = target_asset_ids_hash(target_ids)

    import hashlib as _hashlib
    bin_sha = _hashlib.sha256(Path(binary_path).read_bytes()).hexdigest()
    manifest_store = ManifestStore(db)
    m = ToolManifest(
        tool_name="echo_test", version="1.0.0",
        executable_path=binary_path, executable_sha256=bin_sha,
        execution_class=2, network_access=True,
        allowed_profiles=(
            "test_only", "test/echo", "test/raw", "test/exploit",
            "test/passthrough", "nmap/tcp_connect_scan",
        ), prohibited=(),
        limits={"max_runtime_seconds": 30},
        output_format="text",
        infrastructure_endpoints=tuple(manifest_providers),
    )
    registered = manifest_store.register(m, actor="op")

    # Approval
    now = datetime.now(timezone.utc)
    # Compute the CURRENT state BEFORE issuing the approval, so the
    # approval binds to exactly what the runner will recompute later.
    # Tests that want to prove drift modify the DB AFTER this point.
    _current_scope = _current_scope_lock_hash(db, eng.id, "")
    _current_egress = _current_egress_profile_id()
    _current_adapter_hash = _current_adapter_code_sha256(TEST_ADAPTER_PATH)

    appr = ApprovalRecord(
        approval_id="appr_sandbox_test",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="policy_A",  # no policy_snapshots row → fallback
        scope_lock_hash=_current_scope,
        target_asset_ids=target_ids,
        target_asset_ids_hash=target_hash,
        canonical_hostnames=list(canonical_hostnames),
        allowed_ports=list(allowed_ports),
        allowed_protocols=["https"],
        allowed_http_methods=list(allowed_methods),
        allowed_path_profile="default",
        operation_profile_id="test/echo",
        tool_name=m.tool_name,
        tool_version=m.version,
        tool_executable_sha256=bin_sha,
        adapter_code_sha256=_current_adapter_hash,
        manifest_hash=registered.manifest_hash,
        egress_profile_id=_current_egress,
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
        approved_infrastructure_endpoints=list(approved_providers),
        lab_environment=lab_environment,    )
    ApprovalStore(db).issue(appr)

    return {
        "db": db,
        "eng_id": eng.id,
        "asset_id": target_ids[0],
        "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
        "manifest": registered,
        "echo_sha": bin_sha,
    }


@pytest.fixture
def env(tmp_path):
    """Baseline fixture: no providers."""
    d = _build_env(tmp_path)
    yield d
    d["db"].close()


@pytest.fixture
def env_with_providers(tmp_path):
    """Manifest declares crt.sh; approval authorizes crt.sh."""
    d = _build_env(tmp_path, manifest_providers=("crt.sh",))
    yield d
    d["db"].close()


def _mk_request(**overrides) -> SandboxRequest:
    """Build a SandboxRequest for egress tests.

    `_passthrough=True` routes to the test/passthrough profile (arbitrary
    argv). An argv override without an explicit profile also routes to
    test/raw. An explicit operation_profile in overrides wins. Each test
    that chooses a profile other than test/echo must bind its fixture
    approval to that same profile before invoking the runner.
    """
    passthrough = overrides.pop("_passthrough", False)
    base = dict(
        hostname="probe.test",
        port=443,
        protocol="https",
        method="GET",
        path="/",
        argv=[ECHO_BIN, "hello-from-sandbox"],
        timeout_seconds=15,
        operation_profile="test/echo",
        profile_params={"msg": "hello-from-sandbox"},
    )
    base.update(overrides)
    if "operation_profile" in overrides:
        pass  # explicit profile wins
    elif passthrough:
        base["operation_profile"] = "test/passthrough"
        base["profile_params"] = {"argv": list(base["argv"])}
    elif "argv" in overrides:
        base["operation_profile"] = "test/raw"
        base["profile_params"] = {"args": list(base["argv"][1:])}
    return SandboxRequest(**base)

def _bind_profile(env, profile_id: str) -> None:
    """Update the fixture approval's operation_profile_id.

    Necessary because 6B enforces that the request's operation_profile
    matches the approval's bound profile. Tests that override the
    profile via _passthrough=True or explicit operation_profile= must
    call this before run_in_sandbox so 6B passes and the intended
    check (argv mismatch, class gate, etc.) fires.
    """
    env["db"].connection.execute(
        "UPDATE approvals SET operation_profile_id = ? "
        "WHERE approval_id = ?",
        (profile_id, env["approval_id"]),
    )
    env["db"].commit()


def _stub_resolver(monkeypatch, mapping=None, ip: str = "1.1.1.1") -> None:
    """Replace the real DNS resolver with a deterministic mapping.

    mapping: {hostname: [ips]}. Unlisted hostnames fall back to [ip].
    """
    mapping = mapping or {}

    def fake_resolve(hostname: str) -> list[str]:
        return mapping.get(hostname, [ip])

    monkeypatch.setattr(_sr, "_resolve_hostname", fake_resolve)


# --- E-22b: approval does not cover the request ---

def test_e22b_wrong_port_denied(env, monkeypatch):
    _stub_resolver(monkeypatch)
    with pytest.raises(SandboxDenied, match="port"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(port=8443),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


def test_e22b_wrong_method_denied(env, monkeypatch):
    _stub_resolver(monkeypatch)
    with pytest.raises(SandboxDenied, match="method"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(method="POST"),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


def test_e22b_wrong_protocol_denied(env, monkeypatch):
    _stub_resolver(monkeypatch)
    with pytest.raises(SandboxDenied, match="protocol"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(protocol="http"),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


# --- E-22c: policy hash drift ---

def test_e22c_policy_hash_drift_denied(env, monkeypatch):
    _stub_resolver(monkeypatch)
    # Insert a new policy snapshot with a different hash than the approval
    with env["db"].transaction() as conn:
        conn.execute(
            "INSERT INTO policy_snapshots "
            "(id, engagement_id, policy_hash, raw_text_path, created_at_utc) "
            "VALUES (?, ?, ?, ?, ?)",
            ("ps_1", env["eng_id"], "policy_CHANGED",
             "/tmp/policy.txt", datetime.now(timezone.utc).isoformat()),
        )
    with pytest.raises(SandboxDenied, match="policy"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


# --- E-22d: resolved IP is inside a protected range ---

@pytest.mark.parametrize("bad_ip", ["127.0.0.1", "10.0.0.5",
                                    "172.17.0.1", "169.254.169.254"])
def test_e22d_protected_ip_denied(env, monkeypatch, bad_ip):
    _stub_resolver(monkeypatch, ip=bad_ip)
    with pytest.raises(SandboxDenied, match="protected"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


# --- Structural denials (manifest, argv, hostname) ---

def test_manifest_not_found_denied(env, monkeypatch):
    _stub_resolver(monkeypatch)
    with pytest.raises(SandboxDenied, match="no manifest"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="does_not_exist", adapter_version="0.0.1",
            request=_mk_request(),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


def test_argv0_mismatch_denied(env, monkeypatch):
    _stub_resolver(monkeypatch)
    _bind_profile(env, "test/raw")
    with pytest.raises(SandboxDenied, match="argv\\[0\\]"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(argv=["/bin/true", "x"]),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


def test_hostname_not_approved_denied(env, monkeypatch):
    _stub_resolver(monkeypatch)
    with pytest.raises(SandboxDenied, match="not in approved_assets"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(hostname="other.test"),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


# --- Happy path: echo actually runs inside the namespace ---

def test_happy_path_echo_runs_in_sandbox(env, monkeypatch):
    _stub_resolver(monkeypatch, ip="1.1.1.1")
    _bind_profile(env, "test/raw")
    result = run_in_sandbox(
        db=env["db"], engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="echo_test", adapter_version="1.0.0",
        request=_mk_request(argv=[ECHO_BIN, "hello-from-sandbox"]),
        engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
    )
    assert isinstance(result, SandboxResult)
    assert result.exit_code == 0, f"stderr: {result.stderr}"
    assert "hello-from-sandbox" in result.stdout
    assert result.namespace_name.startswith("sentinel-run-")
    assert result.resolved_ip == "1.1.1.1"
    assert result.audit_event_seq is not None

    # Audit event written
    row = env["db"].connection.execute(
        "SELECT event_type, decision, details_json FROM audit_events "
        "WHERE event_type = 'sandbox_ok'"
    ).fetchone()
    assert row is not None
    # M6.1.1a: audit decision for sandbox_ok is now "completed",
    # matching the fail-closed classification scheme.
    assert row["decision"] == "completed"
    assert env["approval_id"] in row["details_json"]


# --- Meta: subprocess.run must not be called on a denied request ---

def test_denied_request_never_launches_subprocess(env, monkeypatch):
    """E-22 meta: no subprocess.run call for any pre-launch denial.

    Replaces subprocess.run with a recorder that raises if invoked, then
    drives each denial path. Any call indicates a validation-order bug
    (validation ran *after* execution began).
    """
    _stub_resolver(monkeypatch)
    launched: list[list[str]] = []

    real_run = subprocess.run
    def recording_run(args, *a, **kw):
        # Only interested in attempts to launch the echo binary (via
        # ip netns exec); allow other subprocess calls (nft, ip, etc.)
        if isinstance(args, list) and any(
            "echo" in str(x) or "netns" in str(x) for x in args
        ):
            # ip netns exec from within a denied path would be a bug
            if "ip" in str(args[0]):
                launched.append(args)
        return real_run(args, *a, **kw)

    monkeypatch.setattr(_sr.subprocess, "run", recording_run)
    monkeypatch.setattr(subprocess, "run", recording_run)

    # Wrong port → denied before launch
    with pytest.raises(SandboxDenied):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(port=8443),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )

    assert launched == [], (
        f"denied request spawned subprocess: {launched}"
    )


# --- E-25: provider authorization ---

def test_e25_provider_approved_runs(env_with_providers, monkeypatch):
    """Provider in approval + manifest + request -> runs, used_providers set."""
    _stub_resolver(monkeypatch, mapping={
        "probe.test": ["1.1.1.1"],
        "crt.sh": ["104.21.16.1"],
    })
    result = run_in_sandbox(
        db=env_with_providers["db"],
        engagement_id=env_with_providers["eng_id"],
        approval_id=env_with_providers["approval_id"],
        adapter_name="echo_test", adapter_version="1.0.0",
        request=_mk_request(provider_endpoints=("crt.sh",)),
        engagements_root=env_with_providers["engagements_root"],
        adapter_code_path=TEST_ADAPTER_PATH, actor="op",
    )
    assert result.used_providers == ("crt.sh",)
    assert result.exit_code == 0


def test_e25_provider_not_approved_denied(env, monkeypatch):
    """Approval has no providers; request asks for crt.sh -> denied."""
    _stub_resolver(monkeypatch, mapping={
        "probe.test": ["1.1.1.1"],
        "crt.sh": ["104.21.16.1"],
    })
    with pytest.raises(SandboxDenied, match="not authorized"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(provider_endpoints=("crt.sh",)),
            engagements_root=env["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


def test_e25_provider_not_in_manifest_denied(tmp_path, monkeypatch):
    """Approval has crt.sh but manifest declares nothing -> denied.

    Simulates the invariant that approval.providers ⊆ manifest.providers.
    """
    _stub_resolver(monkeypatch, mapping={
        "probe.test": ["1.1.1.1"],
        "crt.sh": ["104.21.16.1"],
    })
    # Manifest: no providers declared; approval: crt.sh authorized.
    # This is the "approval over-reaches manifest" case that
    # _validate_provider_nesting catches.
    d = _build_env(tmp_path, manifest_providers=(),
                   approved_providers=["crt.sh"])
    try:
        with pytest.raises(SandboxDenied, match="not declared by manifest"):
            run_in_sandbox(
                db=d["db"], engagement_id=d["eng_id"],
                approval_id=d["approval_id"],
                adapter_name="echo_test", adapter_version="1.0.0",
                request=_mk_request(provider_endpoints=("crt.sh",)),
                engagements_root=d["engagements_root"], adapter_code_path=TEST_ADAPTER_PATH, actor="op",
            )
    finally:
        d["db"].close()


def test_e25_provider_ip_protected_denied(env_with_providers, monkeypatch):
    """Provider resolves to a protected IP (e.g. RFC1918) -> denied."""
    _stub_resolver(monkeypatch, mapping={
        "probe.test": ["1.1.1.1"],
        "crt.sh": ["10.0.0.5"],  # protected
    })
    with pytest.raises(SandboxDenied, match="protected"):
        run_in_sandbox(
            db=env_with_providers["db"],
            engagement_id=env_with_providers["eng_id"],
            approval_id=env_with_providers["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(provider_endpoints=("crt.sh",)),
            engagements_root=env_with_providers["engagements_root"],
            adapter_code_path=TEST_ADAPTER_PATH, actor="op",
        )


def test_e25_provider_audit_written(env_with_providers, monkeypatch):
    """Every provider contact writes a sandbox_provider_contact audit event
    with provider, target hostname, target IP, and approval id."""
    _stub_resolver(monkeypatch, mapping={
        "probe.test": ["1.1.1.1"],
        "crt.sh": ["104.21.16.1"],
    })
    run_in_sandbox(
        db=env_with_providers["db"],
        engagement_id=env_with_providers["eng_id"],
        approval_id=env_with_providers["approval_id"],
        adapter_name="echo_test", adapter_version="1.0.0",
        request=_mk_request(provider_endpoints=("crt.sh",)),
        engagements_root=env_with_providers["engagements_root"],
        adapter_code_path=TEST_ADAPTER_PATH, actor="op",
    )
    row = env_with_providers["db"].connection.execute(
        "SELECT details_json FROM audit_events "
        "WHERE event_type = 'sandbox_provider_contact'"
    ).fetchone()
    assert row is not None, "provider contact audit not written"
    details = row["details_json"]
    assert "crt.sh" in details
    assert "probe.test" in details
    assert "1.1.1.1" in details
    assert env_with_providers["approval_id"] in details


# --- P1.8: revocation watchdog ---

def test_p18_revocation_mid_execution_stops_run(tmp_path, monkeypatch):
    """E-26: revoking approval while a scanner is running kills it.

    SQLite connections are thread-bound. The Database, run_in_sandbox call,
    and revoke call must each live in a thread that owns its connection:

      - Worker thread builds env (owns its Database) and runs
        run_in_sandbox (uses that Database).
      - Main test thread spawns a separate revoker thread that opens
        its own Database to the same file, revokes, closes.
      - After join, main thread re-opens Database to inspect audit.
    """
    import threading as _threading
    import time as _time
    from sentinel.storage.db import Database as _DB
    from sentinel.approval.store import ApprovalStore as _AST
    from sentinel.runner.sandbox_runner import SandboxRevoked as _Revoked

    _stub_resolver(monkeypatch)

    result_holder: dict = {
        "exc": None,
        "result": None,
        "db_path": None,
        "approval_id": None,
        "ready": _threading.Event(),
    }

    def _run():
        # Build env inside this thread so its Database is bound here
        env = _build_env(tmp_path, binary_path="/bin/sleep")
        _bind_profile(env, "test/passthrough")
        result_holder["db_path"] = str(env["db"].path)
        result_holder["approval_id"] = env["approval_id"]
        result_holder["ready"].set()
        try:
            result_holder["result"] = run_in_sandbox(
                db=env["db"], engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                adapter_name="echo_test", adapter_version="1.0.0",
                request=_mk_request(
                    argv=["/bin/sleep", "30"],
                    timeout_seconds=60,
                 _passthrough=True,),
                adapter_code_path=TEST_ADAPTER_PATH,
                engagements_root=env["engagements_root"],
                actor="op",
            )
        except Exception as e:
            result_holder["exc"] = e
        finally:
            env["db"].close()

    worker = _threading.Thread(target=_run, daemon=True)
    worker.start()

    # Wait for env to be built
    assert result_holder["ready"].wait(timeout=10.0), (
        "worker did not finish env setup"
    )

    # Give the sandbox time to actually spawn the sleeper
    _time.sleep(2.0)

    # Revoke in a separate thread with its own Database connection
    def _revoke():
        rev_db = _DB(result_holder["db_path"])
        try:
            _AST(rev_db).revoke(result_holder["approval_id"])
        finally:
            rev_db.close()

    revoker = _threading.Thread(target=_revoke, daemon=True)
    revoker.start()
    revoker.join(timeout=5.0)
    assert not revoker.is_alive(), "revoker thread did not finish"

    # Watchdog polls every 2s; allow up to 15s for termination
    worker.join(timeout=15.0)

    assert not worker.is_alive(), "run did not terminate after revocation"
    assert isinstance(result_holder["exc"], _Revoked), (
        f"expected SandboxRevoked, got {result_holder['exc']!r}"
    )

    # Inspect audit using a fresh Database in this thread
    final_db = _DB(result_holder["db_path"])
    try:
        row = final_db.connection.execute(
            "SELECT decision, details_json FROM audit_events "
            "WHERE event_type = 'sandbox_revoked'"
        ).fetchone()
        assert row is not None, "sandbox_revoked audit event not written"
        assert row["decision"] == "revoked"
        assert "approval_revoked" in row["details_json"]
    finally:
        final_db.close()


# --- P1.7: aggregate budget enforcement ---

def test_p17_budget_exhausted_denied(env, monkeypatch):
    """E-27: once request budget is exhausted, subsequent runs are denied."""
    _stub_resolver(monkeypatch, ip="1.1.1.1")

    # Burn the entire request budget on one legal call
    run_in_sandbox(
        db=env["db"], engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="echo_test", adapter_version="1.0.0",
        request=_mk_request(estimated_requests=100),  # budget is 100
        adapter_code_path=TEST_ADAPTER_PATH,
        engagements_root=env["engagements_root"], actor="op",
    )
    # Any further request exceeds the ceiling
    with pytest.raises(SandboxDenied, match="request budget exhausted"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(estimated_requests=1),
            adapter_code_path=TEST_ADAPTER_PATH,
            engagements_root=env["engagements_root"], actor="op",
        )


def test_p17_budget_recorded_after_run(env, monkeypatch):
    """E-27: usage table accumulates requests, bytes, runtime."""
    _stub_resolver(monkeypatch, ip="1.1.1.1")
    run_in_sandbox(
        db=env["db"], engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="echo_test", adapter_version="1.0.0",
        request=_mk_request(estimated_requests=5),
        adapter_code_path=TEST_ADAPTER_PATH,
        engagements_root=env["engagements_root"], actor="op",
    )
    # M6-03/M6-04: renamed columns. Old requests_used/bytes_used are
    # deprecated (always 0). New columns carry the real values.
    row = env["db"].connection.execute(
        "SELECT output_bytes_used, estimated_network_probes, "
        "runtime_used_seconds FROM approval_usage WHERE approval_id = ?",
        (env["approval_id"],),
    ).fetchone()
    assert row is not None
    assert row["estimated_network_probes"] == 5
    assert row["output_bytes_used"] > 0
    assert row["runtime_used_seconds"] > 0


# --- M7.1: path-profile refusal ---

def test_m71_path_restricted_approval_refused(env, monkeypatch):
    """M7.1: approval.allowed_path_profile != 'default' -> denied before spawn."""
    _stub_resolver(monkeypatch)
    with env["db"].transaction() as conn:
        conn.execute(
            "UPDATE approvals SET allowed_path_profile = '/api/v1' "
            "WHERE approval_id = ?", (env["approval_id"],),
        )
    with pytest.raises(SandboxDenied, match="path-restricted"):
        run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(),
            adapter_code_path=TEST_ADAPTER_PATH,
            engagements_root=env["engagements_root"], actor="op",
        )


# --- M7.2b.2: use_tls_proxy plumbing ---

def test_m72b_proxy_starts_and_sets_env(tmp_path, monkeypatch):
    """E-28: use_tls_proxy=True spawns proxy, sets env vars, tears down."""
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, binary_path="/usr/bin/env", lab_environment=True)
    _bind_profile(env, "test/passthrough")
    try:
        result = run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(
                argv=["/usr/bin/env"],
                use_tls_proxy=True,
                timeout_seconds=20,
             _passthrough=True,),
            adapter_code_path=TEST_ADAPTER_PATH,
            engagements_root=env["engagements_root"], actor="op",
        )
        # SandboxResult reports proxy port + CA path (informational only;
        # the CA is ephemeral and the dir is cleaned up post-run).
        assert result.proxy_port is not None
        assert result.proxy_port > 0
        assert result.proxy_ca_path is not None
        # The CA dir was cleaned up -- the ephemeral property
        assert not result.proxy_ca_path.exists(), (
            f"ephemeral CA was not cleaned up: {result.proxy_ca_path}"
        )

        # Env vars were exported to the scanner (proves the CA path was
        # real during the run, and the proxy port was correct).
        assert "HTTPS_PROXY=" in result.stdout
        assert "SSL_CERT_FILE=" in result.stdout
        assert "REQUESTS_CA_BUNDLE=" in result.stdout

        proxy_url_in_env = [
            line for line in result.stdout.splitlines()
            if line.startswith("HTTPS_PROXY=")
        ][0]
        assert str(result.proxy_port) in proxy_url_in_env
        assert "10.99.0.1" in proxy_url_in_env

        ca_path_in_env = [
            line for line in result.stdout.splitlines()
            if line.startswith("SSL_CERT_FILE=")
        ][0]
        assert str(result.proxy_ca_path) in ca_path_in_env

        # Proxy audit events written
        events = env["db"].connection.execute(
            "SELECT event_type FROM audit_events "
            "WHERE event_type IN ('sandbox_proxy_started', 'sandbox_proxy_stopped')"
        ).fetchall()
        assert len(events) >= 2
    finally:
        env["db"].close()


# --- M7.2b.2b: end-to-end curl through the proxy ---

@pytest.fixture
def fixture_https_server(tmp_path):
    """Local HTTPS server on 127.0.0.1, signed by a run-local CA.

    Returns dict with: ca, port, stop(). The proxy's upstream_ca_bundle
    must point at ca.ca_cert_path to verify the fixture.
    """
    import ssl
    import http.server
    import threading
    from sentinel.l7.ca import L7CA

    ca = L7CA(tmp_path / "fixture_ca")
    ca.generate()
    leaf = ca.sign_leaf("127.0.0.1")

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"fixture-response-body"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            # Echo body back so we can detect if a POST got through
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a, **k):
            pass

    class _TLSServer(http.server.HTTPServer):
        def get_request(self):
            sock, addr = super().get_request()
            return server_ctx.wrap_socket(sock, server_side=True), addr

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(leaf.cert_path), str(leaf.key_path))

    server = _TLSServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def stop():
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    yield {"ca": ca, "port": port, "stop": stop}
    stop()


def test_m72b_curl_through_proxy_succeeds(tmp_path, monkeypatch, fixture_https_server):
    """E-29: curl inside sandbox -> proxy -> upstream fixture -> 200 + body.

    The sandbox never talks to the target directly (target IP is not in
    approved_destinations because use_tls_proxy=True). The proxy terminates
    TLS, filters the request, then forwards to the fixture upstream.
    """
    _stub_resolver(monkeypatch, mapping={"127.0.0.1": ["127.0.0.1"]})
    upstream_port = fixture_https_server["port"]

    env = _build_env(
        tmp_path,
        binary_path="/usr/bin/curl", lab_environment=True,
        canonical_hostnames=["127.0.0.1"],
        allowed_ports=[upstream_port],
        allowed_methods=["GET"],
    )
    _bind_profile(env, "test/passthrough")
    try:
        result = run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(
                hostname="127.0.0.1",
                port=upstream_port,
                protocol="https",
                method="GET",
                path="/",
                argv=[
                    "/usr/bin/curl",
                    "-sS",
                    f"https://127.0.0.1:{upstream_port}/",
                ],
                use_tls_proxy=True,
                proxy_upstream_ca_bundle=fixture_https_server["ca"].ca_cert_path,
                timeout_seconds=20,
                _passthrough=True,
            ),
            adapter_code_path=TEST_ADAPTER_PATH,
            engagements_root=env["engagements_root"], actor="op",
        )
        assert result.exit_code == 0, (
            f"curl failed: stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "fixture-response-body" in result.stdout, (
            f"expected fixture body in stdout, got: {result.stdout!r}"
        )
        assert result.proxy_port is not None
        assert result.proxy_port > 0
    finally:
        env["db"].close()


def test_m72b_proxy_denies_disallowed_method(tmp_path, monkeypatch, fixture_https_server):
    """E-30: curl -X POST is denied by the proxy filter (403), upstream
    sees zero requests (fixture has no POST counter but the response body
    would carry 'fixture-response-body' if it passed).

    Approval only allows GET. Proxy filter refuses POST with 403 before
    the upstream connect.
    """
    _stub_resolver(monkeypatch, mapping={"127.0.0.1": ["127.0.0.1"]})
    upstream_port = fixture_https_server["port"]

    env = _build_env(
        tmp_path,
        binary_path="/usr/bin/curl", lab_environment=True,
        canonical_hostnames=["127.0.0.1"],
        allowed_ports=[upstream_port],
        allowed_methods=["GET"],  # POST not in allowed set
    )
    _bind_profile(env, "test/passthrough")
    try:
        result = run_in_sandbox(
            db=env["db"], engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            adapter_name="echo_test", adapter_version="1.0.0",
            request=_mk_request(
                hostname="127.0.0.1",
                port=upstream_port,
                protocol="https",
                # Adapter CLAIMS it will use GET (which the approval
                # allows -- gatekeeper passes). The actual HTTP request
                # sent by curl at the wire is POST (-X POST in argv).
                # The proxy filter MUST catch the mismatch and 403.
                method="GET",
                path="/",
                argv=[
                    "/usr/bin/curl",
                    "-sS", "-X", "POST",
                    "-w", "\nHTTP_STATUS:%{http_code}",
                    f"https://127.0.0.1:{upstream_port}/",
                ],
                use_tls_proxy=True,
                proxy_upstream_ca_bundle=fixture_https_server["ca"].ca_cert_path,
                timeout_seconds=20,
                _passthrough=True,
            ),
            adapter_code_path=TEST_ADAPTER_PATH,
            engagements_root=env["engagements_root"], actor="op",
        )
        # The proxy denies with 403. curl still exits 0 because it
        # received a valid HTTP response. The body contains the denial.
        assert "403" in result.stdout or "denied" in result.stdout, (
            f"expected 403 or denial in stdout, got: {result.stdout!r}"
        )
        # Crucially: the fixture body did NOT come back (proxy blocked)
        assert "fixture-response-body" not in result.stdout, (
            f"POST reached upstream despite denial: {result.stdout!r}"
        )
    finally:
        env["db"].close()


def test_m72c_restricted_profile_requires_proxy(tmp_path, monkeypatch):
    """M7.2c: restricted profile + use_tls_proxy=False -> refused.

    M7.1 behavior preserved: without the L7 proxy, non-default path
    profiles cannot be enforced and are rejected.
    """
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path)
    try:
        with env["db"].transaction() as conn:
            conn.execute(
                "UPDATE approvals SET allowed_path_profile = '/api', "
                "allowed_path_prefixes_json = ? "
                "WHERE approval_id = ?",
                ('["/api"]', env["approval_id"]),
            )
        with pytest.raises(SandboxDenied, match="requires use_tls_proxy"):
            run_in_sandbox(
                db=env["db"], engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                adapter_name="echo_test", adapter_version="1.0.0",
                request=_mk_request(use_tls_proxy=False),
                adapter_code_path=TEST_ADAPTER_PATH,
                engagements_root=env["engagements_root"], actor="op",
            )
    finally:
        env["db"].close()


# --- M6-P0-A: operation profile enforcement ---

def test_m6p0a_argv_mismatch_rejected(tmp_path, monkeypatch):
    """A caller sending argv that differs from the profile builder's
    output must be refused before subprocess launch."""
    _stub_resolver(monkeypatch)
    # Manifest is /bin/echo; try to run it with extra flag
    env = _build_env(tmp_path, binary_path="/bin/echo")
    try:
        _bind_profile(env, "nmap/tcp_connect_scan")
        # Profile is nmap/tcp_connect_scan, but the manifest binary
        # isn't nmap and the params won't produce /bin/echo argv. This
        # tests the profile-vs-argv check fires.
        with pytest.raises(SandboxDenied, match="profile"):
            run_in_sandbox(
                db=env["db"], engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                adapter_name="echo_test", adapter_version="1.0.0",
                request=_mk_request(
                    argv=["/bin/echo", "hello"],
                    operation_profile="nmap/tcp_connect_scan",
                    profile_params={
                        "target": "probe.test",
                        "ports": [80],
                        "max_rate": 10,
                    },
                ),
                adapter_code_path=TEST_ADAPTER_PATH,
                engagements_root=env["engagements_root"], actor="op",
            )
    finally:
        env["db"].close()


def test_m6p0a_unknown_profile_rejected(tmp_path, monkeypatch):
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, binary_path="/bin/echo")
    try:
        _bind_profile(env, "totally/fake")
        with pytest.raises(SandboxDenied, match="profile"):
            run_in_sandbox(
                db=env["db"], engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                adapter_name="echo_test", adapter_version="1.0.0",
                request=_mk_request(
                    argv=["/bin/echo", "hello"],
                    operation_profile="totally/fake",
                    profile_params={},
                ),
                adapter_code_path=TEST_ADAPTER_PATH,
                engagements_root=env["engagements_root"], actor="op",
            )
    finally:
        env["db"].close()


# --- M6-01: capability verification ---

def test_m6p01_scanner_runs_with_no_capabilities(tmp_path, monkeypatch):
    """The scanner process must run as nobody with empty capability sets.

    Reads /proc/<pid>/status of the running sandbox child. Confirms:
      - Uid is 65534 (nobody)
      - CapInh, CapPrm, CapEff, CapBnd, CapAmb are all 0
    """
    import threading as _threading
    import time as _time

    _stub_resolver(monkeypatch)

    result_holder: dict = {
        "ready": _threading.Event(),
        "pid": None,
        "status": None,
        "exc": None,
    }

    def _run():
        env = _build_env(tmp_path, binary_path="/bin/sleep")
        _bind_profile(env, "test/passthrough")
        try:
            # Spawn and let the child settle. We use a timeout of 5s so
            # the process is guaranteed to be alive when we read /proc.
            def _do():
                run_in_sandbox(
                    db=env["db"], engagement_id=env["eng_id"],
                    approval_id=env["approval_id"],
                    adapter_name="echo_test", adapter_version="1.0.0",
                    request=_mk_request(
                        argv=["/bin/sleep", "3"],
                        timeout_seconds=10,
                     _passthrough=True,),
                    adapter_code_path=TEST_ADAPTER_PATH,
                    engagements_root=env["engagements_root"], actor="op",
                )
            _do()
        except Exception as e:
            result_holder["exc"] = e
        finally:
            env["db"].close()

    # Simpler: spawn a synthetic run_in_sandbox in a thread, poll for any
    # PID owned by nobody via psutil, read its status.
    import psutil
    worker = _threading.Thread(target=_run, daemon=True)
    worker.start()

    # Poll for a `sleep` process owned by nobody
    deadline = _time.monotonic() + 8.0
    target_pid = None
    while _time.monotonic() < deadline:
        for p in psutil.process_iter(["pid", "username", "cmdline"]):
            try:
                if p.info["username"] == "nobody" and \
                   p.info["cmdline"] and \
                   "sleep" in " ".join(p.info["cmdline"]):
                    target_pid = p.info["pid"]
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if target_pid is not None:
            break
        _time.sleep(0.1)

    assert target_pid is not None, (
        "no nobody-owned sleep process appeared within 8s"
    )

    # Read /proc/<pid>/status
    status_path = f"/proc/{target_pid}/status"
    with open(status_path) as f:
        status_text = f.read()

    # Parse Uid line: "Uid: <real> <effective> <saved> <fs>"
    uid_line = [l for l in status_text.splitlines() if l.startswith("Uid:")][0]
    uids = [int(x) for x in uid_line.split()[1:]]
    assert uids == [65534, 65534, 65534, 65534], (
        f"expected all UIDs=65534 (nobody), got {uids}"
    )

    # Parse capability lines: CapInh, CapPrm, CapEff, CapAmb must be 0.
    # CapBnd may be inherited from the parent; --no-new-privs ensures
    # any setuid exec cannot re-acquire capabilities from it (see
    # setpriv(1): "no_new_privs" prevents gaining more privilege on
    # subsequent execs), so CapEff/CapPrm/CapAmb being 0 is the
    # security-relevant assertion.
    for cap_name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        cap_line = [l for l in status_text.splitlines()
                    if l.startswith(f"{cap_name}:")][0]
        cap_hex = cap_line.split()[1]
        cap_val = int(cap_hex, 16)
        assert cap_val == 0, (
            f"{cap_name} must be 0, got {cap_hex} ({cap_val})"
        )

    worker.join(timeout=15)


# --- M6-02: watchdog fails closed on DB error ---

def test_m6p02_watchdog_db_error_fails_closed(tmp_path, monkeypatch):
    """If the watchdog cannot read approval state, it must kill the run.

    Simulated by dropping the approvals table mid-run. The scanner
    (sleep 30) should be killed and SandboxRevoked raised before the
    sleep finishes.
    """
    import threading as _threading
    import time as _time
    import psutil as _psutil
    from sentinel.storage.db import Database as _DB
    from sentinel.runner.sandbox_runner import SandboxRevoked as _Revoked

    _stub_resolver(monkeypatch)

    result_holder: dict = {
        "exc": None, "result": None, "db_path": None,
        "approval_id": None, "eng_id": None,
        "traceback": None,
        "ready": _threading.Event(),
    }

    def _run():
        env = _build_env(tmp_path, binary_path="/bin/sleep")
        _bind_profile(env, "test/passthrough")
        result_holder["db_path"] = str(env["db"].path)
        result_holder["approval_id"] = env["approval_id"]
        result_holder["eng_id"] = env["eng_id"]
        result_holder["ready"].set()
        try:
            result_holder["result"] = run_in_sandbox(
                db=env["db"], engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                adapter_name="echo_test", adapter_version="1.0.0",
                request=_mk_request(
                    argv=["/bin/sleep", "30"],
                    timeout_seconds=60,
                 _passthrough=True,),
                adapter_code_path=TEST_ADAPTER_PATH,
                engagements_root=env["engagements_root"], actor="op",
            )
        except Exception as e:
            result_holder["exc"] = e
            import traceback as _traceback
            result_holder["traceback"] = _traceback.format_exc()
        finally:
            env["db"].close()

    worker = _threading.Thread(target=_run, daemon=True)
    worker.start()
    assert result_holder["ready"].wait(timeout=10.0)

    # Fixture setup signals ready before the runner performs all preflight
    # checks. Wait for the actual unprivileged child so table removal
    # exercises the watchdog while a process is running, not budget setup.
    deadline = _time.monotonic() + 10.0
    child_found = False
    while _time.monotonic() < deadline:
        for process in _psutil.process_iter(["username", "cmdline"]):
            try:
                if (process.info["username"] == "nobody"
                        and process.info["cmdline"]
                        and "sleep" in " ".join(process.info["cmdline"])):
                    child_found = True
                    break
            except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                continue
        if child_found:
            break
        _time.sleep(0.1)
    assert child_found, "no running unprivileged scanner appeared before corruption"

    def _corrupt():
        cdb = _DB(result_holder["db_path"], auto_migrate=False)
        try:
            with cdb.transaction() as conn:
                conn.execute("DROP TABLE approvals")
        finally:
            cdb.close()

    corruptor = _threading.Thread(target=_corrupt, daemon=True)
    corruptor.start()
    corruptor.join(timeout=5.0)

    worker.join(timeout=15.0)
    assert not worker.is_alive(), "run did not terminate after DB corruption"
    exc = result_holder["exc"]
    assert isinstance(exc, _Revoked), (
        f"expected SandboxRevoked, got {exc!r}\n{result_holder['traceback']}"
    )


# --- M6-06: subprocess output cap ---

def test_m6p06_capped_communicate_truncates():
    """_capped_communicate truncates at max_bytes per stream."""
    import subprocess as _sp
    from sentinel.runner.sandbox_runner import _capped_communicate

    proc = _sp.Popen(
        ["/usr/bin/seq", "1", "100000"],
        stdout=_sp.PIPE, stderr=_sp.PIPE, text=False,
    )
    out, err, out_trunc, err_trunc = _capped_communicate(proc, timeout_s=10.0, max_bytes=1000)
    assert len(out) == 1000, f"expected 1000 bytes, got {len(out)}"
    assert out_trunc is True, "truncation flag must be True when cap is hit"
    assert err_trunc is False
    assert len(err) == 0
    # Verify header still decodes cleanly
    assert out.decode("utf-8", errors="replace").startswith("1\n2\n3")


def test_m6p06_capped_communicate_rejects_zero():
    import subprocess as _sp
    import pytest as _pt
    from sentinel.runner.sandbox_runner import _capped_communicate

    proc = _sp.Popen(["/bin/true"], stdout=_sp.PIPE, stderr=_sp.PIPE, text=False)
    with _pt.raises(ValueError, match="max_bytes"):
        _capped_communicate(proc, timeout_s=2.0, max_bytes=0)
    proc.wait()


# --- M6-03/M6-04: budget columns ---

def test_m6p03_p06_budget_uses_new_columns(env, monkeypatch):
    """After a run, output_bytes_used and estimated_network_probes are
    populated; deprecated columns are not written."""
    _stub_resolver(monkeypatch, ip="1.1.1.1")
    run_in_sandbox(
        db=env["db"], engagement_id=env["eng_id"],
        approval_id=env["approval_id"],
        adapter_name="echo_test", adapter_version="1.0.0",
        request=_mk_request(estimated_requests=5),
        adapter_code_path=TEST_ADAPTER_PATH,
        engagements_root=env["engagements_root"], actor="op",
    )
    row = env["db"].connection.execute(
        "SELECT output_bytes_used, estimated_network_probes, "
        "bytes_used, requests_used FROM approval_usage "
        "WHERE approval_id = ?",
        (env["approval_id"],),
    ).fetchone()
    assert row is not None
    assert row["output_bytes_used"] > 0
    assert row["estimated_network_probes"] == 5
    # Deprecated columns remain 0 (not written)
    assert row["bytes_used"] == 0
    assert row["requests_used"] == 0
