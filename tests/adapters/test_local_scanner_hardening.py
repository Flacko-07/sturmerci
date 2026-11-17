# SPDX-License-Identifier: Apache-2.0
"""batch-3 P1: binary digest, bounded output, exit-code handling.

Applies uniformly to bandit, semgrep, trivy. The test builds its own
env — a fake binary that emits `{}`, a real engagement, a registered
manifest — and monkeypatches either `verify_binary_digest` or
`run_isolated_scanner` at the adapter module level. The adapters themselves are
exercised end-to-end up to the mocked boundary; everything after that
boundary (evidence ingestion, audit writes, result construction) runs
for real.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from sentinel.adapters._helpers import BinaryDigestError, CapturedOutput
from sentinel.engagement.store import EngagementStore
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


ADAPTERS = [
    # (adapter_name, error_class_name, run_fn_name, tool_version, profile_name)
    ("bandit", "BanditAdapterError", "run_bandit", "1.8.0", "python_static_analysis"),
    (
        "semgrep",
        "SemgrepAdapterError",
        "run_semgrep",
        "1.90.0",
        "source_static_analysis",
    ),
    ("trivy", "TrivyAdapterError", "run_trivy", "0.57.1", "dependency_scan"),
]


def _make_fake_binary(adapter: str) -> Path:
    bin_dir = Path(tempfile.mkdtemp(prefix=f"sentinel-test-{adapter}-"))
    bin_dir.chmod(0o755)
    script = bin_dir / f"fake_{adapter}"
    NL = chr(10)
    script.write_text("#!/bin/sh" + NL + "cat <<'JSON'" + NL + "{}" + NL + "JSON" + NL)
    script.chmod(0o755)
    return script


def _build_env(tmp_path: Path, adapter: str, version: str, profile: str) -> dict:
    db = Database(tmp_path / f"{adapter}.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name=f"{adapter}-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    src_dir = tmp_path / "engagements" / eng.id / "source"
    src_dir.mkdir(parents=True)
    (src_dir / "app.py").write_text(
        "import os" + chr(10) + "os.system('ls')" + chr(10),
        encoding="utf-8",
    )

    fake_bin = _make_fake_binary(adapter)
    sha = hashlib.sha256(fake_bin.read_bytes()).hexdigest()

    ManifestStore(db).register(
        ToolManifest(
            tool_name=adapter,
            version=version,
            executable_path=str(fake_bin),
            executable_sha256=sha,
            execution_class=0,
            network_access=False,
            allowed_profiles=(profile,),
            prohibited=(),
            limits={"max_runtime_seconds": 60},
            output_format="json",
        ),
        actor="test",
    )

    config_path = None
    if adapter == "semgrep":
        config_path = tmp_path / "rules.yaml"
        config_path.write_text("rules: []" + chr(10), encoding="utf-8")
    trivy_cache = tmp_path / "trivy-cache"
    if adapter == "trivy":
        trivy_cache.mkdir()

    return {
        "db": db,
        "eng_id": eng.id,
        "engagements_root": tmp_path / "engagements",
        "config": str(config_path) if config_path else None,
        "trivy_cache": str(trivy_cache) if adapter == "trivy" else None,
    }


def _invoke(adapter: str, env: dict, monkeypatch):
    import importlib

    mod = importlib.import_module(f"sentinel.adapters.{adapter}")
    fn_name = {a[0]: a[2] for a in ADAPTERS}[adapter]
    fn = getattr(mod, fn_name)
    kwargs = dict(
        db=env["db"],
        engagement_id=env["eng_id"],
        engagements_root=env["engagements_root"],
    )
    if adapter == "semgrep":
        kwargs["config"] = env["config"]
    elif adapter == "trivy":
        monkeypatch.setenv("TRIVY_CACHE_DIR", env["trivy_cache"])
    return fn(**kwargs)


# ====================================================================
# 1. Digest mismatch -> adapter refuses before subprocess
# ====================================================================


@pytest.mark.parametrize("adapter,err_name,_run_fn,_ver,_prof", ADAPTERS)
def test_digest_mismatch_refused(
    tmp_path, monkeypatch, adapter, err_name, _run_fn, _ver, _prof
):
    import importlib

    mod = importlib.import_module(f"sentinel.adapters.{adapter}")
    err_cls = getattr(mod, err_name)
    _, version, profile = None, _ver, _prof
    env = _build_env(tmp_path, adapter, version, profile)

    def fake_verify(*a, **k):
        raise BinaryDigestError("binary digest mismatch for test-bin")

    monkeypatch.setattr(mod, "verify_binary_digest", fake_verify)

    with pytest.raises(err_cls, match="digest mismatch"):
        _invoke(adapter, env, monkeypatch)

    env["db"].close()


# ====================================================================
# 2. Truncated stdout -> result field + audit field
# ====================================================================


@pytest.mark.parametrize("adapter,_err,_run_fn,_ver,_prof", ADAPTERS)
def test_truncated_stdout_propagates(
    tmp_path, monkeypatch, adapter, _err, _run_fn, _ver, _prof
):
    import importlib

    mod = importlib.import_module(f"sentinel.adapters.{adapter}")
    env = _build_env(tmp_path, adapter, _ver, _prof)

    fake = CapturedOutput(
        stdout="{}",
        stderr="",
        returncode=0,
        timed_out=False,
        truncated_stdout=True,
        truncated_stderr=False,
    )
    monkeypatch.setattr(mod, "run_isolated_scanner", lambda *a, **k: fake)

    result = _invoke(adapter, env, monkeypatch)
    assert result.truncated_stdout is True, (
        f"{adapter}: truncated_stdout not propagated to RunResult"
    )

    event_type = f"{adapter}_run"
    row = (
        env["db"]
        .connection.execute(
            "SELECT details_json FROM audit_events WHERE event_type=?",
            (event_type,),
        )
        .fetchone()
    )
    assert row is not None, f"{adapter}: no {event_type} audit event"
    details_lower = row["details_json"].lower()
    assert (
        '"truncated_stdout": true' in details_lower
        or '"truncated_stdout":true' in details_lower
    ), f"{adapter}: truncated_stdout not in audit details: {row['details_json'][:200]}"
    env["db"].close()


@pytest.mark.parametrize("adapter,_err,_run_fn,_ver,_prof", ADAPTERS)
def test_timeout_output_and_status_are_persisted(
    tmp_path, monkeypatch, adapter, _err, _run_fn, _ver, _prof
):
    import importlib

    mod = importlib.import_module(f"sentinel.adapters.{adapter}")
    env = _build_env(tmp_path, adapter, _ver, _prof)
    fake = CapturedOutput(
        stdout="partial scanner output",
        stderr="diagnostic",
        returncode=-9,
        timed_out=True,
        truncated_stdout=False,
        truncated_stderr=False,
    )
    monkeypatch.setattr(mod, "run_isolated_scanner", lambda *a, **k: fake)

    result = _invoke(adapter, env, monkeypatch)

    assert result.execution_status == "TIMED_OUT"
    row = (
        env["db"]
        .connection.execute(
            "SELECT execution_status, stdout_bytes, stderr_bytes "
            "FROM artifacts WHERE id=?",
            (result.evidence.evidence_id,),
        )
        .fetchone()
    )
    assert row["execution_status"] == "TIMED_OUT"
    assert row["stdout_bytes"] == len(fake.stdout.encode("utf-8"))
    assert row["stderr_bytes"] == len(fake.stderr.encode("utf-8"))
    artifact_text = Path(result.evidence.sanitized_path).read_text(
        encoding="utf-8",
    )
    assert "partial scanner output" in artifact_text
    env["db"].close()


# ====================================================================
# 3. Non-zero exit -> audit decision="error"
# ====================================================================


@pytest.mark.parametrize("adapter,_err,_run_fn,_ver,_prof", ADAPTERS)
def test_nonzero_exit_raises(
    tmp_path, monkeypatch, adapter, _err, _run_fn, _ver, _prof
):
    """(end-to-end fix) Tool that exits non-zero raises before evidence
    write. The prior contract — write "{}" as evidence, report 0
    findings, record decision='error' — silently masked every real
    invocation failure (bad argv, missing binary, permissions). The
    live end-to-end run caught this: `bandit scan` argv was wrong,
    exited 2, wrote 2 bytes of "{}", reported "0 findings" while the
    scanner had never even parsed a file.
    """
    import importlib

    mod = importlib.import_module(f"sentinel.adapters.{adapter}")
    err_cls = getattr(mod, _err)
    env = _build_env(tmp_path, adapter, _ver, _prof)

    # returncode=2: distinct from "0 findings" (0) and "findings found" (1).
    fake = CapturedOutput(
        stdout="{}",
        stderr="fatal: bad argv",
        returncode=2,
        timed_out=False,
        truncated_stdout=False,
        truncated_stderr=False,
    )
    monkeypatch.setattr(mod, "run_isolated_scanner", lambda *a, **k: fake)

    with pytest.raises(err_cls, match="exited 2"):
        _invoke(adapter, env, monkeypatch)

    # Stronger contract: NO evidence written on a failed run.
    row = (
        env["db"]
        .connection.execute(
            "SELECT COUNT(*) AS c FROM artifacts WHERE engagement_id=?",
            (env["eng_id"],),
        )
        .fetchone()
    )
    assert row["c"] == 0, (
        f"{adapter}: evidence was written despite tool failure "
        f"({row['c']} artifacts) — silent failure contract regressed"
    )
    env["db"].close()
