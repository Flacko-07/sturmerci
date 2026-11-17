# SPDX-License-Identifier: Apache-2.0
"""Gitleaks adapter. Class 0, no network.

Wraps the pinned Gitleaks binary with the exact flags validated in
docs/gitleaks-schema-8.30.1.md. Rejects any report whose Secret or Match
field is not the literal string "REDACTED" -- defense-in-depth against
--redact silently failing.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.storage.db import Database, coerce_db
from sentinel.engagement.store import EngagementStore
from sentinel.tools.manifests import ManifestStore
from sentinel.adapters._helpers import (
    execution_status_for_capture, ingest_incomplete_capture,
    run_isolated_scanner,
)
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.evidence.redact import redact
from sentinel.audit.store import AuditStore


REDACTED = "REDACTED"

REQUIRED_FIELDS = frozenset({
    "RuleID", "Description", "File",
    "StartLine", "EndLine", "StartColumn", "EndColumn",
    "Match", "Secret", "Entropy",
    "Author", "Email", "Date", "Commit", "Message",
    "SymlinkFile", "Tags", "Fingerprint",
})


class AdapterError(Exception):
    """Generic adapter failure (manifest missing, engagement wrong state, etc.)."""


class ManifestDriftError(AdapterError):
    """Binary on disk no longer matches the pinned SHA-256."""


class GitleaksOutputError(AdapterError):
    """Report is malformed, missing fields, or contains unredacted material."""


@dataclass(frozen=True, slots=True)
class GitleaksFinding:
    rule_id: str
    description: str
    file: str
    start_line: int
    end_line: int
    fingerprint: str
    entropy: float
    tags: list[str]


@dataclass(frozen=True, slots=True)
class GitleaksRunResult:
    engagement_id: str
    manifest_id: str
    findings_count: int
    findings: list[GitleaksFinding]
    evidence: IngestResult
    process_exit_code: int
    duration_seconds: float
    execution_status: str = "COMPLETED"
    truncated_stdout: bool = False
    truncated_stderr: bool = False


def _verify_binary_digest(path: str, expected: str) -> None:
    binary = Path(path)
    if not binary.exists():
        raise ManifestDriftError(f"binary not found: {binary}")
    h = hashlib.sha256(binary.read_bytes()).hexdigest()
    if h != expected:
        raise ManifestDriftError(
            f"binary digest mismatch: expected {expected[:16]}... got {h[:16]}..."
        )


def parse_and_validate(report_bytes: bytes) -> list[dict[str, Any]]:
    """Parse the report and enforce the schema contract.

    Raises GitleaksOutputError if the report is malformed, missing a required
    field on any finding, or contains an unredacted Secret/Match.
    """
    if not report_bytes:
        return []
    try:
        data = json.loads(report_bytes)
    except json.JSONDecodeError as e:
        raise GitleaksOutputError(f"report is not valid JSON: {e}") from e
    if not isinstance(data, list):
        raise GitleaksOutputError(
            f"report top-level must be an array, got {type(data).__name__}"
        )
    for i, f in enumerate(data):
        if not isinstance(f, dict):
            raise GitleaksOutputError(f"finding[{i}] is not an object")
        missing = REQUIRED_FIELDS - f.keys()
        if missing:
            raise GitleaksOutputError(
                f"finding[{i}] missing required fields: {sorted(missing)}"
            )
        if f["Secret"] != REDACTED:
            raise GitleaksOutputError(
                f"finding[{i}] Secret not redacted (rule={f.get('RuleID')!r}); "
                "refusing to ingest unredacted secret"
            )
        # Gitleaks --redact preserves surrounding match context and may keep
        # the last few characters of the secret as a fingerprint
        # (e.g. 'REDACTEDkP4'). Accept any Match that contains the REDACTED
        # marker; the pipeline's redacted_suffix rule strips the suffix before
        # persistence. An empty Match is permitted for tools that omit it.
        if f["Match"] and "REDACTED" not in f["Match"]:
            raise GitleaksOutputError(
                f"finding[{i}] Match not redacted (rule={f.get('RuleID')!r}); "
                "refusing to ingest unredacted context"
            )
    return data


def _to_finding(raw: dict[str, Any]) -> GitleaksFinding:
    desc, _ = redact(str(raw["Description"]))
    file_s, _ = redact(str(raw["File"]))
    return GitleaksFinding(
        rule_id=str(raw["RuleID"]),
        description=desc,
        file=file_s,
        start_line=int(raw["StartLine"]),
        end_line=int(raw["EndLine"]),
        fingerprint=str(raw["Fingerprint"]),
        entropy=float(raw["Entropy"]),
        tags=[str(t) for t in (raw.get("Tags") or [])],
    )


def run_gitleaks(
    db: Database | Path | str,
    *,
    engagement_id: str,
    engagements_root: Path,
    scan_subdir: str,
    tool_name: str = "gitleaks",
    tool_version: str = "8.30.1",
    actor: str = "operator",
) -> GitleaksRunResult:
    """Run Gitleaks against engagements_root/engagement_id/scan_subdir.

    Preconditions checked in order:
      1. engagement exists and is 'active'
      2. manifest registered for (tool_name, tool_version)
      3. manifest is class 0 with network_access False
      4. ManifestStore.verify() passes (DB-side drift check)
      5. binary SHA-256 on disk matches the manifest
      6. source directory exists

    If any check fails, no subprocess is launched.
    """
    db_obj, owns_db = coerce_db(db)
    try:
        # 1. Engagement state
        eng = EngagementStore(db_obj).get(engagement_id)
        if eng is None:
            raise AdapterError(f"engagement {engagement_id!r} not found")
        if eng.state != "active":
            raise AdapterError(
                f"engagement state is {eng.state!r}; must be 'active' to scan"
            )

        # 2. Persistent manifest is authoritative for tool registration.
        mstore = ManifestStore(db_obj)
        manifest = mstore.get_by_tool_version(tool_name, tool_version)
        if manifest is None:
            raise AdapterError(
                f"no registered manifest for {tool_name!r} {tool_version!r}"
            )

        # 3. Manifest policy
        if manifest.manifest.execution_class != 0:
            raise AdapterError(
                f"manifest execution_class={manifest.manifest.execution_class}; "
                "this adapter is class-0 only"
            )
        if manifest.manifest.network_access:
            raise AdapterError("manifest grants network access; refusing")

        # 4. DB-side manifest integrity
        ok, reason = mstore.verify(manifest.id)
        if not ok:
            raise AdapterError(f"manifest DB drift: {reason}")

        # 5. Binary on disk
        _verify_binary_digest(
            manifest.manifest.executable_path,
            manifest.manifest.executable_sha256,
        )

        # 7. Source path -- must resolve inside the engagement directory.
        # Guards against three escapes in one check:
        #   - traversal:       scan_subdir = "../../etc"
        #   - absolute path:   scan_subdir = "/etc"  (Path.joinpath drops root)
        #   - symlink escape:  engagement/{id}/source -> /etc
        # .resolve() collapses symlinks and dot segments before comparison.
        engagement_root = (engagements_root / engagement_id).resolve()
        source = (engagement_root / scan_subdir).resolve()
        if not source.is_relative_to(engagement_root):
            raise AdapterError(
                f"scan_subdir {scan_subdir!r} escapes engagement directory "
                f"(resolved to {source}, expected under {engagement_root})"
            )
        if not source.exists():
            raise AdapterError(f"source does not exist: {source}")
        if not source.is_dir():
            raise AdapterError(f"source is not a directory: {source}")

        # Run
        report_dir = Path(tempfile.mkdtemp(prefix="gitleaks-output-"))
        report_path = report_dir / "report.json"
        try:
            cmd = [
                manifest.manifest.executable_path,
                "detect",
                "--source", str(source),
                "--report-format", "json",
                "--report-path", str(report_path),
                "--redact",
                "--no-git",
                "--exit-code", "0",
                "--no-banner",
            ]
            timeout = int(manifest.manifest.limits.get("max_runtime_seconds", 300))
            t0 = time.monotonic()
            capture = run_isolated_scanner(
                cmd, input_path=source, timeout_seconds=timeout,
                writable_dir=report_dir,
            )
            duration = time.monotonic() - t0

            if capture.timed_out or capture.truncated_stdout or capture.truncated_stderr:
                report_bytes = b""
                if report_path.is_file():
                    cap_bytes = int(manifest.manifest.limits.get(
                        "max_output_megabytes", 25
                    )) * 1024 * 1024
                    with report_path.open("rb") as report_file:
                        report_bytes = report_file.read(cap_bytes + 1)
                    if len(report_bytes) > cap_bytes:
                        report_bytes = report_bytes[:cap_bytes]
                evidence = ingest_incomplete_capture(
                    db_obj, engagements_root=engagements_root,
                    engagement_id=engagement_id,
                    source_name=f"gitleaks_{tool_version}_partial.txt",
                    actor=actor, capture=capture, event_type="gitleaks_run",
                    content_bytes=report_bytes or None,
                )
                return GitleaksRunResult(
                    engagement_id=engagement_id, manifest_id=manifest.id,
                    findings_count=0, findings=[], evidence=evidence,
                    process_exit_code=capture.returncode,
                    duration_seconds=duration,
                    execution_status=execution_status_for_capture(capture),
                    truncated_stdout=capture.truncated_stdout,
                    truncated_stderr=capture.truncated_stderr,
                )

            # Strict exit-code check. gitleaks exits 0 with --exit-code 0;
            # any non-zero exit means the scan failed (bad args, missing
            # binary, permission error) — do NOT write partial report as
            # if it were a clean scan.
            if capture.returncode != 0:
                raise AdapterError(
                    f"gitleaks exited {capture.returncode}: "
                    f"{(capture.stderr or '')[:300]!r}"
                )
            # Bounded report read. gitleaks writes the report to a file,
            # not stdout. Cap at the manifest's max_output_megabytes (or
            # 25 MiB default) — a hostile repo could produce a huge
            # report file that fills memory.
            if report_path.exists():
                report_size = report_path.stat().st_size
                cap_bytes = int(
                    manifest.manifest.limits.get(
                        "max_output_megabytes", 25
                    )
                ) * 1024 * 1024
                if report_size > cap_bytes:
                    raise AdapterError(
                        f"gitleaks report {report_size} bytes exceeds "
                        f"limit {cap_bytes} bytes — refusing to load"
                    )
                report_bytes = report_path.read_bytes()
            else:
                report_bytes = b"[]"

            # 8. Parse and validate
            raw_findings = parse_and_validate(report_bytes)

            # 9. Ingest as evidence
            evidence = ingest_evidence(
                db_obj,
                engagements_root=engagements_root,
                engagement_id=engagement_id,
                source_name=f"gitleaks_{tool_version}.json",
                content_type="application/json",
                content=report_bytes,
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

            # 10. Audit
            AuditStore(db_obj).append(
                engagement_id=engagement_id,
                actor=actor,
                event_type="gitleaks_run",
                decision="ok" if capture.returncode == 0 else "error",
                details={
                    "manifest_id": manifest.id,
                    "manifest_hash": manifest.manifest_hash,
                    "tool": tool_name,
                    "tool_version": tool_version,
                    "scan_subdir": scan_subdir,
                    "findings_count": len(raw_findings),
                    "evidence_id": evidence.evidence_id,
                    "process_exit_code": capture.returncode,
                    "isolation_backend": capture.isolation_backend,
                    "duration_seconds": round(duration, 3),
                },
            )

            findings = [_to_finding(f) for f in raw_findings]
            return GitleaksRunResult(
                engagement_id=engagement_id,
                manifest_id=manifest.id,
                findings_count=len(findings),
                findings=findings,
                evidence=evidence,
                process_exit_code=capture.returncode,
                duration_seconds=duration,
                execution_status=execution_status_for_capture(capture),
                truncated_stdout=capture.truncated_stdout,
                truncated_stderr=capture.truncated_stderr,
            )
        finally:
            import shutil
            shutil.rmtree(report_dir, ignore_errors=True)
    finally:
        if owns_db:
            db_obj.close()
