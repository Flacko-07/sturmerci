# SPDX-License-Identifier: Apache-2.0
"""Semgrep adapter integration test with fake binary."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from sentinel.engagement.store import EngagementStore
from sentinel.adapters.semgrep import (
    run_semgrep, parse_output, SemgrepFinding,
    SemgrepAdapterError,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


FAKE_OUTPUT = '''{
  "results": [
    {
      "check_id": "python.lang.security.audit.eval-use",
      "path": "/tmp/source/example.py",
      "start": {"line": 10, "col": 1},
      "end": {"line": 10, "col": 20},
      "extra": {
        "severity": "WARNING",
        "message": "Detected use of eval()",
        "metadata": {"category": "security"}
      }
    }
  ]
}'''


def _make_fake_semgrep(tmp_path: Path) -> Path:
    import tempfile
    bin_dir = Path(tempfile.mkdtemp(prefix="sentinel-test-bin-sg-"))
    bin_dir.chmod(0o755)
    script = bin_dir / "fake_semgrep"
    NL = chr(10)
    script.write_text(
        "#!/bin/sh" + NL
        + "cat <<'JSON'" + NL
        + FAKE_OUTPUT + NL
        + "JSON" + NL
    )
    script.chmod(0o755)
    return script


def _register_manifest(db, binary_path: str, version: str = "1.90.0") -> None:
    h = hashlib.sha256(Path(binary_path).read_bytes()).hexdigest()
    m = ToolManifest(
        tool_name="semgrep", version=version,
        executable_path=binary_path, executable_sha256=h,
        execution_class=0, network_access=False,
        allowed_profiles=("source_static_analysis",),
        prohibited=("remote_rules",),
        limits={"max_runtime_seconds": 60},
        output_format="json",
    )
    ManifestStore(db).register(m, actor="test")


def test_parse_output_finds_eval(tmp_path):
    findings = parse_output(FAKE_OUTPUT)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id.startswith("python.lang.security")
    assert f.severity == "WARNING"
    assert f.start_line == 10


def test_parse_output_handles_empty():
    assert parse_output("") == []
    assert parse_output("{}") == []
    assert parse_output("not json") == []


def test_run_semgrep_happy_path(tmp_path):
    # Set up engagement
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab", program_name="semgrep-test", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    # Fake source dir under engagement
    src = tmp_path / "engagements" / eng.id / "source"
    src.mkdir(parents=True)
    (src / "example.py").write_text("eval('1+1')\n")

    # Fake semgrep binary
    binary = _make_fake_semgrep(tmp_path)
    _register_manifest(db, str(binary))
    config = tmp_path / "fake-rules"
    config.write_text("rules: []\n", encoding="utf-8")

    result = run_semgrep(
        db=db, engagement_id=eng.id,
        engagements_root=tmp_path / "engagements",
        scan_subdir="source",
        config=str(config),
        timeout_seconds=10,
    )
    assert result.findings_count == 1
    assert result.evidence.evidence_id.startswith("ev_")
    db.close()


def test_refuses_on_traversal(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab", program_name="x", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")
    binary = _make_fake_semgrep(tmp_path)
    _register_manifest(db, str(binary))

    with pytest.raises(SemgrepAdapterError, match="escapes"):
        run_semgrep(
            db=db, engagement_id=eng.id,
            engagements_root=tmp_path / "engagements",
            scan_subdir="../..",
        )
    db.close()


def test_refuses_on_inactive_engagement(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab", program_name="x", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    # Still in draft
    binary = _make_fake_semgrep(tmp_path)
    _register_manifest(db, str(binary))
    with pytest.raises(SemgrepAdapterError, match="not active"):
        run_semgrep(
            db=db, engagement_id=eng.id,
            engagements_root=tmp_path / "engagements",
        )
    db.close()
