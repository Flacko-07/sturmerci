# SPDX-License-Identifier: Apache-2.0
"""ExifTool adapter — document/file metadata extraction (Class 0).

Runs `exiftool -json <dir>` against a directory of files the operator
has placed under engagement/<scan_subdir>/. Emits findings for files
whose metadata contains security-relevant fields (GPS, author, creator,
software, comment, embedded XMP/thumbnail). The finding records the
*names* of sensitive fields only; the raw JSON (with actual values) is
stored as evidence via ingest_evidence, which applies redaction.

Constraints:
  - Class 0 (local only). No network. Same discipline as bandit/trivy.
  - Binary SHA-256 verified against manifest before launch.
  - Output capped (5 MiB stdout / 1 MiB stderr).
  - scan_subdir must resolve under engagement/<eng_id>/ (path
    containment, same as gitleaks/semgrep/bandit/trivy).
  - Only JSON output format is permitted (prohibited flags block
    -csv/-htmlFormat/-X/-php).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sentinel.adapters._helpers import (
    BinaryDigestError, CapturedOutput, run_isolated_scanner, verify_binary_digest,
    execution_status_for_capture, ingest_incomplete_capture,
)
from sentinel.audit.store import AuditStore
from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


EXIFTOOL_TOOL_NAME = "exiftool"
EXIFTOOL_VERSION = "13.00"      # updated by Block 1's registration run
PROFILE = "metadata_extraction"

# Fields whose presence in a file's metadata is worth flagging. Matched
# by prefix: any field starting with one of these names is considered
# sensitive. Values are NOT recorded in the finding — only names — to
# avoid persisting GPS coordinates / author names in structured form.
# The raw JSON (with values) goes to evidence; ingest_evidence redacts
# known secret shapes, and the operator reads the full metadata there.
SENSITIVE_FIELD_PREFIXES = (
    "GPS",          # GPSLatitude, GPSLongitude, GPSAltitude, ...
    "Author",
    "Creator",
    "Artist",
    "Producer",
    "Comment",
    "Software",     # file format + version -> target fingerprints
    "XMP",          # arbitrary embedded XMP
    "Thumbnail",    # embedded thumbnails can leak pre-edit content
    "IPTC",         # press-agency metadata (by-line, credit, ...)
    "UserComment",
    "OwnerName",
    "SerialNumber",
    "InternalSerialNumber",
    "ImageUniqueID",
    "DocumentAncestors",
    "History",
)


class ExifToolAdapterError(ValueError):
    """ExifTool adapter refused the request."""


@dataclass(frozen=True, slots=True)
class ExifToolFinding:
    file_path: str               # relative to engagement/<scan_subdir>/
    file_type: str               # exiftool's FileType
    file_size: int
    sensitive_fields: list[str]  # names only, never values


@dataclass(frozen=True, slots=True)
class ExifToolRunResult:
    findings: list[ExifToolFinding]
    findings_count: int
    files_scanned: int
    evidence: IngestResult
    process_exit_code: int
    timed_out: bool = False
    truncated_stdout: bool = False
    truncated_stderr: bool = False
    execution_status: str = "COMPLETED"


def _matches_sensitive(field_name: str) -> bool:
    return any(field_name.startswith(p) for p in SENSITIVE_FIELD_PREFIXES)


def parse_output(stdout: str) -> list[ExifToolFinding]:
    """Parse `exiftool -json` output into ExifToolFinding list.

    exiftool emits a JSON array, one object per file, with fields like
    SourceFile, FileType, FileSize, plus format-specific metadata. We
    keep only files that have at least one sensitive field.
    """
    if not stdout or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out: list[ExifToolFinding] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        src = str(entry.get("SourceFile", "") or "")
        if not src:
            continue
        file_type = str(entry.get("FileType", "") or "")
        try:
            file_size = int(entry.get("FileSize", 0) or 0)
        except (TypeError, ValueError):
            file_size = 0
        sensitive = sorted(
            k for k in entry.keys()
            if k not in ("SourceFile", "FileType", "FileSize",
                         "ExifToolVersion", "Directory", "FileName")
            and _matches_sensitive(k)
        )
        if not sensitive:
            continue
        out.append(ExifToolFinding(
            file_path=src,
            file_type=file_type,
            file_size=file_size,
            sensitive_fields=sensitive,
        ))
    return out


def run_exiftool(
    *,
    db: Database | Path | str,
    engagement_id: str,
    engagements_root: Path,
    scan_subdir: str = "source",
    actor: str = "operator",
    timeout_seconds: int = 120,
) -> ExifToolRunResult:
    """Run pinned ExifTool against engagement/<scan_subdir>/.

    Class 0: local-only, no network. Refuses if the subdir escapes the
    engagement directory or if the installed binary's SHA-256 doesn't
    match the manifest.
    """
    db_obj, owns = coerce_db(db)
    try:
        eng = EngagementStore(db_obj).get(engagement_id)
        if eng is None or eng.state != "active":
            raise ExifToolAdapterError(
                f"engagement {engagement_id!r} not active "
                f"(state: {getattr(eng, 'state', 'missing')})"
            )

        manifest = ManifestStore(db_obj).get_by_tool_version(
            EXIFTOOL_TOOL_NAME, EXIFTOOL_VERSION,
        )
        if manifest is None:
            raise ExifToolAdapterError(
                f"no manifest for exiftool {EXIFTOOL_VERSION} — register first"
            )
        if manifest.manifest.network_access:
            raise ExifToolAdapterError(
                "exiftool manifest must be network_access=False"
            )

        try:
            verify_binary_digest(
                manifest.manifest.executable_path,
                manifest.manifest.executable_sha256,
            )
        except BinaryDigestError as e:
            raise ExifToolAdapterError(str(e)) from e

        # Path containment (same discipline as bandit/semgrep/trivy).
        eng_root = (engagements_root / engagement_id).resolve()
        source = (eng_root / scan_subdir).resolve()
        if not source.is_relative_to(eng_root):
            raise ExifToolAdapterError(
                f"scan_subdir {scan_subdir!r} escapes engagement directory"
            )
        if not source.exists() or not source.is_dir():
            raise ExifToolAdapterError(f"source not found: {source}")

        argv = [
            manifest.manifest.executable_path,
            "-json",       # structured output (prohibited_flags blocks csv/html/X/php)
            "-G",          # group names -> prefix fields with group for parsing
            "-n",          # numeric values (avoids "1/500 sec" style strings)
            "-r",          # recursive
            "-q",          # quiet (suppress warnings to stderr)
            str(source),
        ]

        capture = run_isolated_scanner(
            argv, input_path=source, timeout_seconds=timeout_seconds,
        )
        if capture.timed_out or capture.truncated_stdout or capture.truncated_stderr:
            evidence = ingest_incomplete_capture(
                db_obj, engagements_root=engagements_root,
                engagement_id=engagement_id,
                source_name=f"exiftool_{scan_subdir}_partial.txt",
                actor=actor, capture=capture, event_type="exiftool_run",
            )
            findings = parse_output(capture.stdout)
            return ExifToolRunResult(
                findings=findings, findings_count=len(findings),
                files_scanned=0, evidence=evidence,
                process_exit_code=capture.returncode, timed_out=capture.timed_out,
                truncated_stdout=capture.truncated_stdout,
                truncated_stderr=capture.truncated_stderr,
                execution_status=execution_status_for_capture(capture),
            )

        findings = parse_output(capture.stdout or "")

        # Count files (not just findings) for the audit event.
        try:
            _doc = json.loads(capture.stdout or "[]")
            files_scanned = len(_doc) if isinstance(_doc, list) else 0
        except json.JSONDecodeError:
            files_scanned = 0

        evidence = ingest_evidence(
            db_obj, engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"exiftool_{scan_subdir}.json",
            content_type="application/json",
            content=(capture.stdout or "[]").encode("utf-8"),
            actor=actor,
            truncated_output=capture.truncated_stdout or capture.truncated_stderr,
            execution_status=execution_status_for_capture(capture),
            stdout_bytes=len(capture.stdout.encode("utf-8")),
            stderr_bytes=len(capture.stderr.encode("utf-8")),
            output_limit_bytes=5 * 1024 * 1024 + 1024 * 1024,
            stdout_truncated=capture.truncated_stdout,
            stderr_truncated=capture.truncated_stderr,
            timed_out=capture.timed_out,
            terminated=(capture.returncode < 0),
            process_exit_code=capture.returncode,
        )

        AuditStore(db_obj).append(
            engagement_id=engagement_id, actor=actor,
            event_type="exiftool_run",
            decision="ok" if capture.returncode in (0, 1) else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "files_scanned": files_scanned,
                "findings_count": len(findings),
                "evidence_id": evidence.evidence_id,
                "process_exit_code": capture.returncode,
                "timed_out": capture.timed_out,
                "truncated_stdout": capture.truncated_stdout,
            },
        )

        return ExifToolRunResult(
            findings=findings,
            findings_count=len(findings),
            files_scanned=files_scanned,
            evidence=evidence,
            process_exit_code=capture.returncode,
            timed_out=capture.timed_out,
            truncated_stdout=capture.truncated_stdout,
            truncated_stderr=capture.truncated_stderr,
            execution_status=execution_status_for_capture(capture),
        )
    finally:
        if owns:
            db_obj.close()
