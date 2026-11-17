# SPDX-License-Identifier: Apache-2.0
"""nikto adapter — web server scanner (Class 2, active low-impact).

Design decisions:
  - Host:port approval covers the scan target.
  - Tuning is restricted to informational categories (1,2,3). Destructive
    categories 4-9 (XSS, upload, DoS, RFI, RCE, SQLi) are never passed.
    The builder refuses any tunings string outside {1,2,3}.
  - Rate derived from approval.request_rate_budget -> nikto -Pause N.
  - GET only; nikto has no method-override flag.
  - Output parsed defensively against both `vulnerabilities` and `items`
    keys (nikto's JSON schema varies by version).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sentinel.audit.store import AuditStore
from sentinel.approval.store import ApprovalStore
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.runner.sandbox_runner import SandboxRequest, run_in_sandbox
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


NIKTO_TOOL_NAME = "nikto"
NIKTO_VERSION = "2.5.0"  # replaced by Block 2 registration
PROFILE = "web_server_scan"
ALLOWED_TUNINGS = "123"
MAX_RATE = 20  # nikto is slow; cap at 20 rps
MAX_MAXTIME_SECONDS = 900


class NiktoAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class NiktoFinding:
    item_id: str
    method: str
    url: str
    msg: str
    references: str


@dataclass(frozen=True, slots=True)
class NiktoRunResult:
    findings: list[NiktoFinding]
    findings_count: int
    evidence: IngestResult
    banner: str
    process_exit_code: int
    execution_status: str = "COMPLETED"


def parse_output(stdout: str) -> tuple[list[NiktoFinding], str]:
    """Parse nikto -Format json. Returns (findings, banner)."""
    if not stdout or not stdout.strip():
        return [], ""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return [], ""
    if not isinstance(data, dict):
        return [], ""
    banner = str(data.get("banner", "") or "")
    results = data.get("vulnerabilities")
    if not isinstance(results, list):
        results = data.get("items")
    if not isinstance(results, list):
        return [], banner
    out: list[NiktoFinding] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url", "") or "")
        msg = str(r.get("msg", "") or "")
        if not url and not msg:
            continue
        out.append(
            NiktoFinding(
                item_id=str(r.get("id", "") or "")[:20],
                method=str(r.get("method", "") or "")[:10],
                url=url[:500],
                msg=msg[:2000],
                references=str(r.get("references", "") or "")[:500],
            )
        )
    return out, banner


def run_nikto(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_hostname: str,
    port: int,
    scheme: str,
    engagements_root: Path,
    actor: str = "operator",
    timeout_seconds: int = 600,
) -> NiktoRunResult:
    """Run nikto against an approved host:port."""
    db_obj, owns = coerce_db(db)
    try:
        approval = ApprovalStore(db_obj).get(approval_id)
        if approval is None:
            raise NiktoAdapterError(f"approval {approval_id!r} not found")
        if approval.revoked_at_utc:
            raise NiktoAdapterError(f"approval {approval_id!r} revoked")

        rate = max(1, min(int(approval.request_rate_budget), MAX_RATE))
        pause_seconds = max(0.05, round(1.0 / rate, 2))
        maxtime = min(timeout_seconds, MAX_MAXTIME_SECONDS)

        manifest = ManifestStore(db_obj).get_by_tool_version(
            NIKTO_TOOL_NAME,
            NIKTO_VERSION,
        )
        if manifest is None:
            raise NiktoAdapterError(
                f"no manifest for nikto {NIKTO_VERSION} — register first"
            )
        if not manifest.manifest.network_access:
            raise NiktoAdapterError("nikto manifest must be network_access=True")

        params = {
            "hostname": target_hostname,
            "port": port,
            "scheme": scheme,
            "tunings": ALLOWED_TUNINGS,
            "pause_seconds": pause_seconds,
            "max_time_seconds": maxtime,
        }
        # Builder is authoritative; runner rebuilds and compares.
        from sentinel.runner.profiles import build_argv_for_profile

        argv = build_argv_for_profile(
            profile_name="nikto/web_server_scan",
            executable_path=manifest.manifest.executable_path,
            params=params,
        )

        request = SandboxRequest(
            hostname=target_hostname,
            port=port,
            protocol=scheme,
            method="GET",
            path="/",
            argv=argv,
            timeout_seconds=timeout_seconds,
            additional_ports=(),
            provider_endpoints=(),
            requires_target_connection=True,
            estimated_requests=500,
            estimated_output_bytes=500000,
            operation_profile="nikto/web_server_scan",
            profile_params=params,
        )

        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=NIKTO_TOOL_NAME,
            adapter_version=NIKTO_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        findings, banner = parse_output(result.stdout or "")

        evidence = ingest_evidence(
            db_obj,
            engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"nikto_{target_hostname}_{port}.json",
            content_type="application/json",
            content=(result.stdout or "{}").encode("utf-8"),
            actor=actor,
            truncated_output=result.truncated_stdout or result.truncated_stderr,
            execution_status=result.execution_status,
            stdout_bytes=result.stdout_bytes,
            stderr_bytes=result.stderr_bytes,
            output_limit_bytes=result.output_limit_bytes,
            stdout_truncated=result.truncated_stdout,
            stderr_truncated=result.truncated_stderr,
            timed_out=result.timed_out,
            terminated=result.terminated,
            process_exit_code=result.exit_code,
        )

        AuditStore(db_obj).append(
            engagement_id=engagement_id,
            actor=actor,
            event_type="nikto_run",
            decision="ok" if result.exit_code == 0 else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "findings_count": len(findings),
                "rate": rate,
                "tunings": ALLOWED_TUNINGS,
                "evidence_id": evidence.evidence_id,
            },
        )

        return NiktoRunResult(
            findings=findings,
            findings_count=len(findings),
            evidence=evidence,
            banner=banner,
            process_exit_code=result.exit_code,
            execution_status=result.execution_status,
        )
    finally:
        if owns:
            db_obj.close()
