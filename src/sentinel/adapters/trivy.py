# SPDX-License-Identifier: Apache-2.0
"""Trivy adapter — dependency/CVE scanning (Class 0, offline mode).

Uses --offline-scan and a cached vulnerability DB. Refuses to fetch
the DB during a scan (that would be network activity in an adapter
registered as Class 0).
"""

from __future__ import annotations

import json
import os
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


TRIVY_TOOL_NAME = "trivy"
TRIVY_VERSION = "0.57.1"
PROFILE = "dependency_scan"

FORBIDDEN_FLAGS = (
    "--auto-refresh",  # downloads DB during run
    "--download-db-only",  # explicit DB download
    "--skip-db-update=false",  # would allow update
)


class TrivyAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TrivyFinding:
    vuln_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    target: str


@dataclass(frozen=True, slots=True)
class TrivyRunResult:
    findings: list[TrivyFinding]
    findings_count: int
    evidence: IngestResult
    process_exit_code: int = 0
    timed_out: bool = False
    truncated_stdout: bool = False
    truncated_stderr: bool = False
    execution_status: str = "COMPLETED"


def parse_output(stdout: str) -> list[TrivyFinding]:
    if not stdout or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    findings: list[TrivyFinding] = []
    for result in data.get("Results", []) or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", "") or "")
        for v in result.get("Vulnerabilities", []) or []:
            if not isinstance(v, dict):
                continue
            findings.append(
                TrivyFinding(
                    vuln_id=str(v.get("VulnerabilityID", "") or ""),
                    package_name=str(v.get("PkgName", "") or ""),
                    installed_version=str(v.get("InstalledVersion", "") or ""),
                    fixed_version=str(v.get("FixedVersion", "") or ""),
                    severity=str(v.get("Severity", "") or ""),
                    title=str(v.get("Title", "") or "")[:200],
                    target=target,
                )
            )
    return findings


def run_trivy(
    *,
    db: Database | Path | str,
    engagement_id: str,
    engagements_root: Path,
    scan_subdir: str = "source",
    scan_type: str = "fs",
    actor: str = "operator",
    timeout_seconds: int = 300,
) -> TrivyRunResult:
    """Run pinned Trivy in offline mode against a local source dir."""
    db_obj, owns = coerce_db(db)
    try:
        eng = EngagementStore(db_obj).get(engagement_id)
        if eng is None or eng.state != "active":
            raise TrivyAdapterError(f"engagement {engagement_id!r} not active")

        manifest = ManifestStore(db_obj).get_by_tool_version(
            TRIVY_TOOL_NAME,
            TRIVY_VERSION,
        )
        if manifest is None:
            raise TrivyAdapterError(
                f"no manifest for trivy {TRIVY_VERSION} — register first"
            )
        if manifest.manifest.network_access:
            raise TrivyAdapterError("trivy manifest must be network_access=False")

        try:
            verify_binary_digest(
                manifest.manifest.executable_path,
                manifest.manifest.executable_sha256,
            )
        except BinaryDigestError as e:
            raise TrivyAdapterError(str(e)) from e
        eng_root = (engagements_root / engagement_id).resolve()
        source = (eng_root / scan_subdir).resolve()
        if not source.is_relative_to(eng_root):
            raise TrivyAdapterError("scan_subdir escapes engagement directory")
        if not source.exists() or not source.is_dir():
            raise TrivyAdapterError(f"source not found: {source}")

        argv = [
            manifest.manifest.executable_path,
            "fs",
            "--format",
            "json",
            "--quiet",
            "--scanners",
            "vuln",
            "--skip-db-update",
            str(source),
        ]
        for token in argv:
            for forbidden in FORBIDDEN_FLAGS:
                if token == forbidden or token.startswith(
                    forbidden.split("=")[0] + "="
                ):
                    raise TrivyAdapterError(f"forbidden trivy flag: {token!r}")

        cache_path = Path(
            os.environ.get("TRIVY_CACHE_DIR", str(Path.home() / ".cache" / "trivy"))
        ).resolve()
        if not cache_path.is_dir():
            raise TrivyAdapterError(
                "offline Trivy database cache is missing; provide a prepared "
                "TRIVY_CACHE_DIR before running the isolated scanner"
            )
        capture = run_isolated_scanner(
            argv,
            input_path=source,
            timeout_seconds=timeout_seconds,
            extra_readonly=(cache_path,),
            env_overrides={"TRIVY_CACHE_DIR": str(cache_path)},
        )
        if capture.timed_out or capture.truncated_stdout or capture.truncated_stderr:
            evidence = ingest_incomplete_capture(
                db_obj,
                engagements_root=engagements_root,
                engagement_id=engagement_id,
                source_name=f"trivy_{TRIVY_VERSION}_partial.txt",
                actor=actor,
                capture=capture,
                event_type="trivy_run",
            )
            findings = parse_output(capture.stdout)
            return TrivyRunResult(
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

        # (end-to-end fix from bandit) Fail loud instead of silent.
        # A tool that exits non-zero (bad argv, missing binary,
        # permission error) produces no valid findings. Writing "{}"
        # as evidence and reporting "0 findings" is a false negative.
        if capture.returncode not in (0, 1):
            raise TrivyAdapterError(
                f"trivy exited {capture.returncode} "
                f"(expected 0 or 1). "
                f"stderr: {(capture.stderr or '')[:300]!r}"
            )
        if not (capture.stdout or "").strip():
            raise TrivyAdapterError(
                f"trivy produced empty stdout "
                f"(exit={capture.returncode}). "
                f"stderr: {(capture.stderr or '')[:300]!r}"
            )
        try:
            import json as _json_strict

            _json_strict.loads(capture.stdout)
        except Exception as _je:
            raise TrivyAdapterError(
                f"output is not valid JSON: {_je}. "
                f"stdout[:200]={capture.stdout[:200]!r}"
            )

        findings = parse_output(stdout or "")

        evidence = ingest_evidence(
            db_obj,
            engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"trivy_{TRIVY_VERSION}.json",
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
            event_type="trivy_run",
            decision="ok" if capture.returncode in (0, 1) else "error",
            details={
                "manifest_id": manifest.id,
                "findings_count": len(findings),
                "evidence_id": evidence.evidence_id,
                "process_exit_code": capture.returncode,
                "timed_out": capture.timed_out,
                "truncated_stdout": capture.truncated_stdout,
            },
        )

        return TrivyRunResult(
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
