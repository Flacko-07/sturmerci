# SPDX-License-Identifier: Apache-2.0
"""Semgrep adapter — source code static analysis.

Class 0 (local only). Uses run_in_sandbox? No — Class 0 adapters do
not need the namespace because there is no network traffic. They call
subprocess directly with pinned argv (same pattern as Gitleaks).

Actually: Gitleaks follows the pattern of run_captured (bounded) directly
because Class 0. Semgrep will mirror that exactly.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sentinel.audit.store import AuditStore
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.evidence.redact import redact
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore
from sentinel.adapters._helpers import (
    BinaryDigestError, run_isolated_scanner, verify_binary_digest,
    execution_status_for_capture, ingest_incomplete_capture,
)


SEMGREP_TOOL_NAME = "semgrep"
SEMGREP_VERSION = "1.90.0"
PROFILE = "source_static_analysis"

# Semgrep rules MUST come from a local path. Any of these fetches
# from semgrep.dev at runtime, which violates the Class-0 no-network
# contract for this adapter:
#   - config="auto"
#   - config="p/ci", "p/security-audit", or any "p/..." rule pack
#   - config="r/..." (registry)
# Operator must pre-cache rules with `semgrep --save` or point at
# a local rules directory.
DEFAULT_CONFIG = None  # required, no default

# Flags that would force telemetry or remote fetch. Matched by exact
# string only — NOT split on '=' — so --config=<local> is not blocked.
FORBIDDEN_FLAGS = (
    "--enable-metrics",
    "--metrics-on",
)


class SemgrepAdapterError(ValueError):
    """Semgrep adapter refused the request."""


@dataclass(frozen=True, slots=True)
class SemgrepFinding:
    rule_id: str
    severity: str
    file: str
    start_line: int
    end_line: int
    message: str
    category: str


@dataclass(frozen=True, slots=True)
class SemgrepRunResult:
    findings: list[SemgrepFinding]
    findings_count: int
    evidence: IngestResult
    process_exit_code: int
    timed_out: bool = False
    truncated_stdout: bool = False
    truncated_stderr: bool = False
    execution_status: str = "COMPLETED"


def _assert_no_forbidden_flags(argv: list[str]) -> None:
    for token in argv:
        for forbidden in FORBIDDEN_FLAGS:
            if token == forbidden:
                raise SemgrepAdapterError(
                    f"forbidden semgrep flag in argv: {token!r} "
                    "(metrics or remote fetch refused)"
                )


def _validate_config(config: str) -> None:
    # (batch B) Refuse URL-shaped configs. Semgrep accepts `--config=<url>`
    # and will fetch the rules over the network, violating this adapter's
    # Class-0 network_access=False contract. Prior validation caught only
    # the specific forms `auto`, `p/*`, `r/*`. Any `://` is refused.
    if "://" in config:
        raise SemgrepAdapterError(
            f"config {config!r} is a URL — this adapter runs semgrep "
            f"offline (Class 0). Pass a local rules path instead. "
            f"Remote configs are refused to preserve the no-network claim."
        )
    """Refuse remote configs. Local paths (dir or single YAML) allowed."""
    if config in ("auto",):
        raise SemgrepAdapterError(
            "config='auto' fetches from semgrep.dev at runtime; "
            "refused for Class-0 no-network compliance"
        )
    if config.startswith("p/") or config.startswith("r/"):
        raise SemgrepAdapterError(
            f"config={config!r} is a remote rule pack; "
            "pre-cache with `semgrep --save` and use the local path"
        )


def parse_output(stdout: str) -> list[SemgrepFinding]:
    """Parse semgrep --json output."""
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
    findings: list[SemgrepFinding] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        rule_id = str(r.get("check_id", "") or "")
        if not rule_id:
            continue
        path = str(r.get("path", "") or "")
        start = r.get("start", {}) or {}
        end = r.get("end", {}) or {}
        extra = r.get("extra", {}) or {}
        findings.append(SemgrepFinding(
            rule_id=rule_id,
            severity=str(extra.get("severity", "") or ""),
            file=path,
            start_line=int(start.get("line", 0) or 0),
            end_line=int(end.get("line", 0) or 0),
            message=str(extra.get("message", "") or "")[:500],
            category=str(extra.get("metadata", {}).get("category", "") or ""),
        ))
    return findings


def run_semgrep(
    *,
    db: Database | Path | str,
    engagement_id: str,
    engagements_root: Path,
    scan_subdir: str = "source",
    config: str = DEFAULT_CONFIG,
    actor: str = "operator",
    timeout_seconds: int = 300,
) -> SemgrepRunResult:
    """Run pinned Semgrep against engagement/<scan_subdir>/.

    Class 0. No network. Refuses if config points at a URL or if
    forbidden flags would appear.
    """
    db_obj, owns = coerce_db(db)
    try:
        eng = EngagementStore(db_obj).get(engagement_id)
        if eng is None or eng.state != "active":
            raise SemgrepAdapterError(
                f"engagement {engagement_id!r} not active "
                f"(state: {getattr(eng, 'state', 'missing')})"
            )

        manifest = ManifestStore(db_obj).get_by_tool_version(
            SEMGREP_TOOL_NAME, SEMGREP_VERSION,
        )
        if manifest is None:
            raise SemgrepAdapterError(
                f"no manifest for semgrep {SEMGREP_VERSION} — register first"
            )
        if manifest.manifest.network_access:
            raise SemgrepAdapterError("semgrep manifest must be network_access=False")


        try:
            verify_binary_digest(
                manifest.manifest.executable_path,
                manifest.manifest.executable_sha256,
            )
        except BinaryDigestError as e:
            raise SemgrepAdapterError(str(e)) from e
        # Path containment
        eng_root = (engagements_root / engagement_id).resolve()
        source = (eng_root / scan_subdir).resolve()
        if not source.is_relative_to(eng_root):
            raise SemgrepAdapterError(
                f"scan_subdir {scan_subdir!r} escapes engagement directory"
            )
        if not source.exists() or not source.is_dir():
            raise SemgrepAdapterError(f"source not found: {source}")

        if not config:
            raise SemgrepAdapterError(
                "config is required; pass a local rules path. "
                "Remote configs (auto, p/*, r/*) are refused to keep "
                "this adapter offline."
            )
        _validate_config(config)

        argv = [
            manifest.manifest.executable_path,
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            f"--config={config}",
            str(source),
        ]
        _assert_no_forbidden_flags(argv)

        t0 = __import__("time").monotonic()
        config_path = Path(config).resolve(strict=True)
        capture = run_isolated_scanner(
            argv, input_path=source, timeout_seconds=timeout_seconds,
            extra_readonly=(config_path,),
        )
        duration = __import__("time").monotonic() - t0
        if capture.timed_out or capture.truncated_stdout or capture.truncated_stderr:
            evidence = ingest_incomplete_capture(
                db_obj, engagements_root=engagements_root,
                engagement_id=engagement_id,
                source_name=f"semgrep_{SEMGREP_VERSION}_partial.txt",
                actor=actor, capture=capture, event_type="semgrep_run",
            )
            findings = parse_output(capture.stdout)
            return SemgrepRunResult(
                findings=findings, findings_count=len(findings),
                evidence=evidence, process_exit_code=capture.returncode,
                timed_out=capture.timed_out, truncated_stdout=capture.truncated_stdout,
                truncated_stderr=capture.truncated_stderr,
                execution_status=execution_status_for_capture(
                    capture, successful_exit_codes=(0, 1)),
            )
        stdout = capture.stdout

        # (end-to-end fix from bandit) Fail loud instead of silent.
        # A tool that exits non-zero (bad argv, missing binary,
        # permission error) produces no valid findings. Writing "{}"
        # as evidence and reporting "0 findings" is a false negative.
        if capture.returncode not in (0, 1):
            raise SemgrepAdapterError(
                f"semgrep exited {capture.returncode} "
                f"(expected 0 or 1). "
                f"stderr: {(capture.stderr or '')[:300]!r}"
            )
        if not (capture.stdout or "").strip():
            raise SemgrepAdapterError(
                f"semgrep produced empty stdout "
                f"(exit={capture.returncode}). "
                f"stderr: {(capture.stderr or '')[:300]!r}"
            )
        try:
            import json as _json_strict
            _json_strict.loads(capture.stdout)
        except Exception as _je:
            raise SemgrepAdapterError(
                f"output is not valid JSON: {_je}. "
                f"stdout[:200]={capture.stdout[:200]!r}"
            )

        findings = parse_output(stdout or "")

        # Ingest the raw JSON as evidence (hashed; redaction applied)
        evidence = ingest_evidence(
            db_obj, engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"semgrep_{SEMGREP_VERSION}.json",
            content_type="application/json",
            content=(stdout or "{}").encode("utf-8"),
            actor=actor,
            truncated_output=capture.truncated_stdout or capture.truncated_stderr,
            execution_status=execution_status_for_capture(
                capture, successful_exit_codes=(0, 1)),
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
            event_type="semgrep_run",
            decision="ok" if capture.returncode in (0, 1) else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "findings_count": len(findings),
                "evidence_id": evidence.evidence_id,
                "process_exit_code": capture.returncode,
                "timed_out": capture.timed_out,
                "truncated_stdout": capture.truncated_stdout,
                "duration_seconds": round(duration, 3),
            },
        )

        return SemgrepRunResult(
            findings=findings, findings_count=len(findings),
            evidence=evidence, process_exit_code=capture.returncode,
            timed_out=capture.timed_out,
            truncated_stdout=capture.truncated_stdout,
            truncated_stderr=capture.truncated_stderr,
            execution_status=execution_status_for_capture(
                capture, successful_exit_codes=(0, 1)),
        )
    finally:
        if owns:
            db_obj.close()
