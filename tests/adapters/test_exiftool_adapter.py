# SPDX-License-Identifier: Apache-2.0
"""ExifTool adapter tests — hermetic, using the shared _helpers pattern."""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.adapters._helpers import BinaryDigestError, CapturedOutput
from sentinel.adapters.exiftool import (
    run_exiftool, parse_output, ExifToolAdapterError,
)
from sentinel.engagement.store import EngagementStore
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


FAKE_OUTPUT = json.dumps([
    {
        "SourceFile": "/eng/source/document.pdf",
        "FileType": "PDF",
        "FileSize": 12345,
        "ExifToolVersion": 13.00,
        "Author": "Jane Doe",
        "Creator": "Word",
        "GPSLatitude": 37.7749,
        "GPSLongitude": -122.4194,
    },
    {
        "SourceFile": "/eng/source/photo.jpg",
        "FileType": "JPEG",
        "FileSize": 5678,
        "ExifToolVersion": 13.00,
        # no sensitive fields -> skipped
    },
    {
        "SourceFile": "/eng/source/meta.docx",
        "FileType": "DOCX",
        "FileSize": 999,
        "ExifToolVersion": 13.00,
        "Producer": "LibreOffice",
        "History": "...",
    },
])


def test_parse_output_extracts_sensitive_fields():
    findings = parse_output(FAKE_OUTPUT)
    assert len(findings) == 2  # photo.jpg skipped
    pdf = findings[0]
    assert pdf.file_path.endswith("document.pdf")
    assert "GPSLatitude" in pdf.sensitive_fields
    assert "GPSLongitude" in pdf.sensitive_fields
    assert "Author" in pdf.sensitive_fields
    assert "Creator" in pdf.sensitive_fields
    # Values not stored in finding
    assert "Jane Doe" not in str(pdf.sensitive_fields)
    assert "37.7749" not in str(pdf.sensitive_fields)


def test_parse_output_empty():
    assert parse_output("") == []
    assert parse_output("[]") == []
    assert parse_output("not json") == []


def test_parse_output_skips_files_without_sensitive_fields():
    doc = json.dumps([{
        "SourceFile": "/clean.txt",
        "FileType": "TXT",
        "FileSize": 10,
    }])
    assert parse_output(doc) == []


def _make_fake_binary(tmp_path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    p = bin_dir / "exiftool"
    p.write_bytes(b"fake-exiftool")
    return p


def _build_env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab", program_name="exif-test", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    src = tmp_path / "engagements" / eng.id / "source"
    src.mkdir(parents=True)
    (src / "doc.pdf").write_bytes(b"%PDF-1.4 fake")

    bin_path = _make_fake_binary(tmp_path)
    sha = hashlib.sha256(bin_path.read_bytes()).hexdigest()

    from sentinel.adapters.exiftool import EXIFTOOL_VERSION
    ManifestStore(db).register(ToolManifest(
        tool_name="exiftool", version=EXIFTOOL_VERSION,
        executable_path=str(bin_path), executable_sha256=sha,
        execution_class=0, network_access=False,
        allowed_profiles=("metadata_extraction",),
        prohibited=("-w", "-csv", "-htmlFormat", "-X", "-php"),
        limits={"max_runtime_seconds": 60},
        output_format="json",
    ), actor="test")

    return {
        "db": db, "eng_id": eng.id,
        "engagements_root": tmp_path / "engagements",
    }


def test_run_exiftool_happy(tmp_path):
    env = _build_env(tmp_path)
    fake = CapturedOutput(
        stdout=FAKE_OUTPUT, stderr="", returncode=0,
        timed_out=False, truncated_stdout=False, truncated_stderr=False,
    )
    with patch("sentinel.adapters.exiftool.run_isolated_scanner", return_value=fake):
        result = run_exiftool(
            db=env["db"], engagement_id=env["eng_id"],
            engagements_root=env["engagements_root"],
        )
    assert result.files_scanned == 3
    assert result.findings_count == 2
    assert result.evidence.evidence_id.startswith("ev_")
    env["db"].close()


def test_run_exiftool_refuses_digest_mismatch(tmp_path):
    env = _build_env(tmp_path)
    def _bad_verify(*a, **k):
        raise BinaryDigestError("mismatch for test-bin")
    with patch("sentinel.adapters.exiftool.verify_binary_digest", _bad_verify):
        with pytest.raises(ExifToolAdapterError, match="mismatch"):
            run_exiftool(
                db=env["db"], engagement_id=env["eng_id"],
                engagements_root=env["engagements_root"],
            )
    env["db"].close()


def test_run_exiftool_refuses_path_escape(tmp_path):
    env = _build_env(tmp_path)
    with pytest.raises(ExifToolAdapterError, match="escapes"):
        run_exiftool(
            db=env["db"], engagement_id=env["eng_id"],
            engagements_root=env["engagements_root"],
            scan_subdir="../other_engagement",
        )
    env["db"].close()


def test_run_exiftool_timeout_evidence_recorded(tmp_path):
    env = _build_env(tmp_path)
    fake = CapturedOutput(
        stdout="", stderr="", returncode=-9,
        timed_out=True, truncated_stdout=False, truncated_stderr=False,
    )
    with patch("sentinel.adapters.exiftool.run_isolated_scanner", return_value=fake):
        result = run_exiftool(
            db=env["db"], engagement_id=env["eng_id"],
            engagements_root=env["engagements_root"],
        )
    assert result.execution_status == "TIMED_OUT"
    assert result.evidence.execution_status == "TIMED_OUT"
    assert env["db"].connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type='exiftool_run'"
    ).fetchone()[0] == 1
    env["db"].close()
