# SPDX-License-Identifier: Apache-2.0
"""Trivy adapter integration test with fake binary."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path


from sentinel.engagement.store import EngagementStore
from sentinel.adapters.trivy import (
    run_trivy,
    parse_output,
)
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


FAKE_OUTPUT = """{
  "Results": [
    {
      "Target": "/tmp/source/requirements.txt",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-12345",
          "PkgName": "requests",
          "InstalledVersion": "2.0.0",
          "FixedVersion": "2.31.0",
          "Severity": "HIGH",
          "Title": "Requests library vulnerability"
        }
      ]
    }
  ]
}"""


def _make_fake_trivy() -> Path:
    bin_dir = Path(tempfile.mkdtemp(prefix="sentinel-test-bin-tv-"))
    bin_dir.chmod(0o755)
    script = bin_dir / "fake_trivy"
    NL = chr(10)
    script.write_text(
        "#!/bin/sh" + NL + "cat <<'JSON'" + NL + FAKE_OUTPUT + NL + "JSON" + NL
    )
    script.chmod(0o755)
    return script


def _register(db, path: str) -> None:
    h = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    ManifestStore(db).register(
        ToolManifest(
            tool_name="trivy",
            version="0.57.1",
            executable_path=path,
            executable_sha256=h,
            execution_class=0,
            network_access=False,
            allowed_profiles=("dependency_scan",),
            prohibited=("db_download",),
            limits={"max_runtime_seconds": 60},
            output_format="json",
        ),
        actor="test",
    )


def test_parse_output():
    findings = parse_output(FAKE_OUTPUT)
    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2023-12345"
    assert findings[0].severity == "HIGH"


def test_run_trivy_happy_path(tmp_path, monkeypatch):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="trivy-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")
    src = tmp_path / "engagements" / eng.id / "source"
    src.mkdir(parents=True)
    (src / "requirements.txt").write_text("requests==2.0.0\n")
    binary = _make_fake_trivy()
    _register(db, str(binary))
    cache = tmp_path / "trivy-cache"
    cache.mkdir()
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache))

    result = run_trivy(
        db=db,
        engagement_id=eng.id,
        engagements_root=tmp_path / "engagements",
    )
    assert result.findings_count == 1
    assert result.evidence.evidence_id.startswith("ev_")
    db.close()
