# SPDX-License-Identifier: Apache-2.0
"""Bandit adapter — Python static analysis (Class 0, offline).

Bandit analyzes Python source for common security issues (SQL injection
via string formatting, hardcoded passwords, weak crypto, subprocess
shell=True, etc.). Pure Python AST analysis — no network. Same
pattern as Semgrep: run_captured (bounded) with pinned argv, JSON parsing,
evidence ingestion, audit event.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from sentinel.audit.store import AuditStore
from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore
from sentinel.adapters._helpers import (
    BinaryDigestError,
    run_isolated_scanner,
    verify_binary_digest,
    execution_status_for_capture,
    ingest_incomplete_capture,
)


BANDIT_TOOL_NAME = "bandit"
BANDIT_VERSION = "1.8.0"
PROFILE = "python_static_analysis"


class BanditAdapterError(ValueError):
    """Bandit adapter refused the request."""


@dataclass(frozen=True, slots=True)
class BanditFinding:
    test_id: str
    test_name: str
    severity: str
    confidence: str
    file: str
    line: int
    message: str


@dataclass(frozen=True, slots=True)
class BanditRunResult:
    findings: list[BanditFinding]
    findings_count: int
    evidence: IngestResult
    process_exit_code: int
    timed_out: bool = False
    truncated_stdout: bool = False
    truncated_stderr: bool = False
    execution_status: str = "COMPLETED"


def parse_output(stdout: str) -> list[BanditFinding]:
    """Parse bandit -f json output.

    Bandit exits non-zero when it finds issues; the JSON is still valid.
    """
    if not stdout or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if not isinstance(results, list):
        return []
    findings: list[BanditFinding] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        test_id = str(r.get("test_id", "") or "")
        if not test_id:
            continue
        filename = str(r.get("filename", "") or "")
        findings.append(
            BanditFinding(
                test_id=test_id,
                test_name=str(r.get("test_name", "") or ""),
                severity=str(r.get("issue_severity", "") or ""),
                confidence=str(r.get("issue_confidence", "") or ""),
                file=filename,
                line=int(r.get("line_number", 0) or 0),
                message=str(r.get("issue_text", "") or "")[:500],
            )
        )
    return findings


def run_bandit(
    *,
    db: Database | Path | str,
    engagement_id: str,
    engagements_root: Path,
    scan_subdir: str = "source",
    actor: str = "operator",
    timeout_seconds: int = 300,
) -> BanditRunResult:
    """Run pinned Bandit against engagement/<scan_subdir>/ (Python only)."""
    db_obj, owns = coerce_db(db)
    try:
        eng = EngagementStore(db_obj).get(engagement_id)
        if eng is None or eng.state != "active":
            raise BanditAdapterError(
                f"engagement {engagement_id!r} not active "
                f"(state: {getattr(eng, 'state', 'missing')})"
            )

        manifest = ManifestStore(db_obj).get_by_tool_version(
            BANDIT_TOOL_NAME,
            BANDIT_VERSION,
        )
        if manifest is None:
            raise BanditAdapterError(
                f"no manifest for bandit {BANDIT_VERSION} — register first"
            )
        if manifest.manifest.network_access:
            raise BanditAdapterError("bandit manifest must be network_access=False")

        try:
            verify_binary_digest(
                manifest.manifest.executable_path,
                manifest.manifest.executable_sha256,
            )
        except BinaryDigestError as e:
            raise BanditAdapterError(str(e)) from e
        eng_root = (engagements_root / engagement_id).resolve()
        source = (eng_root / scan_subdir).resolve()
        if not source.is_relative_to(eng_root):
            raise BanditAdapterError(
                f"scan_subdir {scan_subdir!r} escapes engagement directory"
            )
        if not source.exists() or not source.is_dir():
            raise BanditAdapterError(f"source not found: {source}")

        # (end-to-end fix) bandit has no `scan` subcommand. The correct
        # form is `bandit -r <path> -f json -q`. Prior argv sent "scan" as
        # a positional, argparse rejected it with exit 2, stdout was empty,
        # adapter wrote "{}" as evidence, findings_count=0. Silent failure.
        argv = [
            manifest.manifest.executable_path,
            "-r",
            str(source),
            "-f",
            "json",
            "-q",
        ]

        t0 = time.monotonic()
        capture = run_isolated_scanner(
            argv,
            input_path=source,
            timeout_seconds=timeout_seconds,
        )
        duration = time.monotonic() - t0
        if capture.timed_out or capture.truncated_stdout or capture.truncated_stderr:
            evidence = ingest_incomplete_capture(
                db_obj,
                engagements_root=engagements_root,
                engagement_id=engagement_id,
                source_name=f"bandit_{BANDIT_VERSION}_partial.txt",
                actor=actor,
                capture=capture,
                event_type="bandit_run",
            )
            findings = parse_output(capture.stdout)
            return BanditRunResult(
                findings=findings,
                findings_count=len(findings),
                evidence=evidence,
                process_exit_code=capture.returncode,
                timed_out=capture.timed_out,
                truncated_stdout=capture.truncated_stdout,
                truncated_stderr=capture.truncated_stderr,
                execution_status=execution_status_for_capture(
                    capture, successful_exit_codes=(0, 1)
                ),
            )
        stdout = capture.stdout

        # Bandit exits 1 when findings exist; JSON on stdout is still valid.
        # (end-to-end fix) Fail loud instead of silent.
        # A previous run with the broken `bandit scan ...` argv exited 2
        # with empty stdout; the adapter wrote "{}" as evidence and
        # printed "Scan complete. Findings: 0" while the actual run had
        # failed. These checks convert every broken-invocation mode into
        # a clear BanditAdapterError before evidence is persisted.
        if capture.returncode not in (0, 1):
            raise BanditAdapterError(
                f"bandit exited {capture.returncode} "
                f"(expected 0 or 1). "
                f"stderr: {(capture.stderr or '')[:300]!r}"
            )
        if not (capture.stdout or "").strip():
            raise BanditAdapterError(
                f"bandit produced empty stdout (exit={capture.returncode}). "
                f"stderr: {(capture.stderr or '')[:300]!r}"
            )
        try:
            import json as _json_strict

            _json_strict.loads(capture.stdout)
        except Exception as _je:
            raise BanditAdapterError(
                f"bandit output is not valid JSON: {_je}. "
                f"stdout[:200]={capture.stdout[:200]!r}"
            )

        findings = parse_output(stdout or "")

        evidence = ingest_evidence(
            db_obj,
            engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"bandit_{BANDIT_VERSION}.json",
            content_type="application/json",
            content=(stdout or "{}").encode("utf-8"),
            actor=actor,
            truncated_output=capture.truncated_stdout or capture.truncated_stderr,
            execution_status=execution_status_for_capture(
                capture, successful_exit_codes=(0, 1)
            ),
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
            engagement_id=engagement_id,
            actor=actor,
            event_type="bandit_run",
            decision="ok" if capture.returncode in (0, 1) else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "findings_count": len(findings),
                "evidence_id": evidence.evidence_id,
                "process_exit_code": capture.returncode,
                "timed_out": capture.timed_out,
                "truncated_stdout": capture.truncated_stdout,
                "isolation_backend": capture.isolation_backend,
                "duration_seconds": round(duration, 3),
            },
        )

        return BanditRunResult(
            findings=findings,
            findings_count=len(findings),
            evidence=evidence,
            process_exit_code=capture.returncode,
            timed_out=capture.timed_out,
            truncated_stdout=capture.truncated_stdout,
            truncated_stderr=capture.truncated_stderr,
            execution_status=execution_status_for_capture(
                capture, successful_exit_codes=(0, 1)
            ),
        )
    finally:
        if owns:
            db_obj.close()
