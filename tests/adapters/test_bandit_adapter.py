# SPDX-License-Identifier: Apache-2.0
"""Bandit adapter integration test with fake binary."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from sentinel.engagement.store import EngagementStore
from sentinel.adapters.bandit import (
    run_bandit,
    parse_output,
    BanditAdapterError,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


FAKE_OUTPUT = """{
  "results": [
    {
      "test_id": "B602",
      "test_name": "subprocess_popen_with_shell_equals_true",
      "issue_severity": "HIGH",
      "issue_confidence": "HIGH",
      "filename": "/tmp/source/app.py",
      "line_number": 42,
      "issue_text": "subprocess call with shell=True"
    }
  ]
}"""


def _make_fake_bandit() -> Path:
    bin_dir = Path(tempfile.mkdtemp(prefix="sentinel-test-bin-bd-"))
    bin_dir.chmod(0o755)
    script = bin_dir / "fake_bandit"
    NL = chr(10)
    script.write_text(
        "#!/bin/sh" + NL + "cat <<'JSON'" + NL + FAKE_OUTPUT + NL + "JSON" + NL
    )
    script.chmod(0o755)
    return script


def _register(db, path: str, version: str = "1.8.0") -> None:
    h = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    ManifestStore(db).register(
        ToolManifest(
            tool_name="bandit",
            version=version,
            executable_path=path,
            executable_sha256=h,
            execution_class=0,
            network_access=False,
            allowed_profiles=("python_static_analysis",),
            prohibited=(),
            limits={"max_runtime_seconds": 60},
            output_format="json",
        ),
        actor="test",
    )


def test_parse_output_finds_shell_true():
    findings = parse_output(FAKE_OUTPUT)
    assert len(findings) == 1
    assert findings[0].test_id == "B602"
    assert findings[0].severity == "HIGH"


def test_parse_empty():
    assert parse_output("") == []
    assert parse_output("not json") == []


def test_run_bandit_happy_path(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="bandit-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")
    src = tmp_path / "engagements" / eng.id / "source"
    src.mkdir(parents=True)
    (src / "app.py").write_text(
        "import subprocess\nsubprocess.call('ls', shell=True)\n"
    )

    _register(db, str(_make_fake_bandit()))
    result = run_bandit(
        db=db,
        engagement_id=eng.id,
        engagements_root=tmp_path / "engagements",
    )
    assert result.findings_count == 1
    assert result.evidence.evidence_id.startswith("ev_")
    db.close()


def test_refuses_on_traversal(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="x",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")
    _register(db, str(_make_fake_bandit()))
    with pytest.raises(BanditAdapterError, match="escapes"):
        run_bandit(
            db=db,
            engagement_id=eng.id,
            engagements_root=tmp_path / "engagements",
            scan_subdir="../../etc",
        )
    db.close()
