# SPDX-License-Identifier: Apache-2.0
"""sqlmap adapter — SQL injection detection (Class 3, intrusive, LAB-ONLY).

Design decisions:
  - Class 3 gate: refuses unless approval.intrusive_authorized=True AND
    approval.lab_environment=True. SandboxRunner enforces this.
  - DETECTION ONLY: --technique=B (boolean-blind), --level=1 --risk=1.
    No data extraction (--dump/--dbs/--tables), no shells (--os-shell/
    --sql-shell), no file operations. Proof-only: we confirm injectability,
    we do not exploit it.
  - Unique per-run output dir (/tmp/sentinel-sqlmap-<uuid>) to avoid
    sqlmap's hostname-only subdir collision (127.0.0.1:18080 vs :18081
    would both write to <root>/127.0.0.1/).
  - Parse the plaintext log at <output-dir>/<hostname>/log. Injectable
    marker: "[INFO] <METHOD> parameter '<name>' appears to be
    '<technique>' injectable". Clean marker: "[CRITICAL] all tested
    parameters do not appear to be injectable".
  - /usr/bin/sqlmap is a Python wrapper. The manifest hashes the wrapper;
    apt upgrade invalidates the approval (correct behavior).
"""
from __future__ import annotations

import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from sentinel.adapters._helpers import prepare_sandbox_dir

from sentinel.audit.store import AuditStore
from sentinel.approval.store import ApprovalStore
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.runner.profiles import build_argv_for_profile
from sentinel.runner.sandbox_runner import SandboxRequest, run_in_sandbox
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


SQLMAP_TOOL_NAME = "sqlmap"
SQLMAP_VERSION = "1.8.4"
PROFILE = "detect"

_INJECTABLE_RE = re.compile(
    r"\[INFO\] (.+?) parameter '([^']+)' appears to be '([^']+)' injectable",
    re.IGNORECASE,
)
_CLEAN_RE = re.compile(
    r"\[CRITICAL\] all tested parameters do not appear to be injectable",
    re.IGNORECASE,
)


class SqlmapAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SqlmapFinding:
    method: str
    parameter: str
    technique: str


@dataclass(frozen=True, slots=True)
class SqlmapRunResult:
    findings: list[SqlmapFinding]
    findings_count: int
    evidence: IngestResult
    log_bytes: int
    process_exit_code: int
    execution_status: str = "COMPLETED"


def parse_log(log_text: str) -> list[SqlmapFinding]:
    """Extract injectable findings from a sqlmap log."""
    if not log_text:
        return []
    out: list[SqlmapFinding] = []
    for line in log_text.splitlines():
        m = _INJECTABLE_RE.search(line)
        if m:
            out.append(SqlmapFinding(
                method=m.group(1).strip(),
                parameter=m.group(2).strip(),
                technique=m.group(3).strip(),
            ))
    return out


def is_clean_run(log_text: str) -> bool:
    return bool(_CLEAN_RE.search(log_text or ""))


def run_sqlmap(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_hostname: str,
    port: int,
    scheme: str,
    engagements_root: Path,
    path: str = "/",
    query: str = "",
    data: str | None = None,
    actor: str = "operator",
    timeout_seconds: int = 300,
) -> SqlmapRunResult:
    """Run sqlmap detection against an approved target (Class 3)."""
    db_obj, owns = coerce_db(db)
    run_id = uuid.uuid4().hex[:16]
    out_dir = Path(f"/tmp/sentinel-sqlmap-{run_id}")
    try:
        approval = ApprovalStore(db_obj).get(approval_id)
        if approval is None:
            raise SqlmapAdapterError(f"approval {approval_id!r} not found")
        if approval.revoked_at_utc:
            raise SqlmapAdapterError(f"approval {approval_id!r} revoked")

        manifest = ManifestStore(db_obj).get_by_tool_version(
            SQLMAP_TOOL_NAME, SQLMAP_VERSION,
        )
        if manifest is None:
            raise SqlmapAdapterError(
                f"no manifest for sqlmap {SQLMAP_VERSION} — register first"
            )
        if not manifest.manifest.network_access:
            raise SqlmapAdapterError(
                "sqlmap manifest must be network_access=True"
            )

        # Create the output dir with world-writable permissions so
        # `nobody` (sandbox uid) can write into it, but `nflacko`
        # (the adapter process) still owns it for cleanup.
        out_dir.mkdir(parents=True, exist_ok=True)
        # (v3 hardening) 0o750 + ACL for nobody, not 0o777.
        prepare_sandbox_dir(out_dir)

        delay = max(1, 5.0 / max(1, approval.request_rate_budget))
        params = {
            "hostname": target_hostname,
            "port": port,
            "scheme": scheme,
            "path": path,
            "query": query,
            "data": data,
            "output_dir": str(out_dir),
            "delay_seconds": round(delay, 1),
            "technique": "B",
        }
        argv = build_argv_for_profile(
            profile_name="sqlmap/detect",
            executable_path=manifest.manifest.executable_path,
            params=params,
        )

        request = SandboxRequest(
            hostname=target_hostname,
            port=port,
            protocol=scheme,
            method="POST" if data else "GET",
            path=f"{path}?{query}" if query else path,
            argv=argv,
            timeout_seconds=timeout_seconds,
            additional_ports=(),
            provider_endpoints=(),
            requires_target_connection=True,
            estimated_requests=max(20, timeout_seconds // 2),
            operation_profile="sqlmap/detect",
            profile_params=params,
        )

        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=SQLMAP_TOOL_NAME,
            adapter_version=SQLMAP_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        # Locate log: <out_dir>/<hostname>/log, fall back to <out_dir>/log
        log_files = list(out_dir.glob("*/log")) or list(out_dir.glob("log"))
        if log_files:
            log_text = log_files[0].read_text(encoding="utf-8", errors="replace")
        else:
            log_text = ""

        findings = parse_log(log_text)
        clean = is_clean_run(log_text)

        evidence = ingest_evidence(
            db_obj, engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"sqlmap_{target_hostname}_{port}.log",
            content_type="text/plain",
            content=(log_text or "[no log produced]").encode("utf-8"),
            actor=actor,
            truncated_output=result.truncated_stdout or result.truncated_stderr,
            execution_status=result.execution_status,
            stdout_bytes=result.stdout_bytes, stderr_bytes=result.stderr_bytes,
            output_limit_bytes=result.output_limit_bytes,
            stdout_truncated=result.truncated_stdout,
            stderr_truncated=result.truncated_stderr,
            timed_out=result.timed_out,
            terminated=result.terminated,
            process_exit_code=result.exit_code,
        )

        AuditStore(db_obj).append(
            engagement_id=engagement_id, actor=actor,
            event_type="sqlmap_run",
            decision="ok" if result.exit_code == 0 else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "domain": target_hostname,
                "port": port,
                "method": "POST" if data else "GET",
                "findings_count": len(findings),
                "clean_run": clean,
                "evidence_id": evidence.evidence_id,
                "exit_code": result.exit_code,
            },
        )

        return SqlmapRunResult(
            findings=findings,
            findings_count=len(findings),
            evidence=evidence,
            log_bytes=len(log_text.encode("utf-8")),
            process_exit_code=result.exit_code,
            execution_status=result.execution_status,
        )
    finally:
        # Best-effort cleanup. Files may be owned by `nobody`; parent
        # dir is owned by us, so rmtree succeeds if tree permissions
        # allow. ignore_errors=True keeps cleanup from masking results.
        shutil.rmtree(out_dir, ignore_errors=True)
        if owns:
            db_obj.close()
