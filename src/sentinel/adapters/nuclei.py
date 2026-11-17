# SPDX-License-Identifier: Apache-2.0
"""nuclei adapter — template-based detection (Class 2, active low-impact).

Template authorization: docs/nuclei-template-intake.md.
Hash format matches `find ... | sort | xargs sha256sum | sha256sum`:
  sha256( <hex>  <path>\n <hex>  <path>\n ... )
"""
from __future__ import annotations

import hashlib
import json
import os
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


NUCLEI_TOOL_NAME = "nuclei"
NUCLEI_VERSION = "3.3.7"
PROFILE = "scan"


class NucleiAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    type: str


@dataclass(frozen=True, slots=True)
class NucleiRunResult:
    findings: list[NucleiFinding]
    findings_count: int
    evidence: IngestResult
    process_exit_code: int
    execution_status: str = "COMPLETED"


def parse_output(jsonl: str) -> list[NucleiFinding]:
    if not jsonl or not jsonl.strip():
        return []
    out: list[NucleiFinding] = []
    for line in jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        info = obj.get("info") or {}
        out.append(NucleiFinding(
            template_id=str(obj.get("template-id", "") or "")[:100],
            name=str(info.get("name", "") or "")[:200],
            severity=str(info.get("severity", "") or "unknown")[:20],
            matched_at=str(obj.get("matched-at", "") or obj.get("host", ""))[:500],
            type=str(obj.get("type", "") or "")[:20],
        ))
    return out


def _compute_templates_hash(base: Path) -> str:
    """Compute hash matching `find | sort | xargs sha256sum | sha256sum`."""
    files = sorted(
        [p for p in base.rglob("*")
         if p.is_file() and p.suffix in (".yaml", ".yml")],
        key=lambda p: str(p),
    )
    h = hashlib.sha256()
    for p in files:
        file_hash = hashlib.sha256(p.read_bytes()).hexdigest()
        # sha256sum format: "<hex>  <path>\n"
        h.update(f"{file_hash}  {p}\n".encode())
    return h.hexdigest()


def _verify_templates_dir() -> None:
    """Recompute template dir hash and compare to pinned value."""
    from sentinel.runner.builtin_profiles import (
        NUCLEI_TEMPLATES_DIR, NUCLEI_TEMPLATES_HASH,
    )
    base = Path(NUCLEI_TEMPLATES_DIR)
    if not base.is_dir():
        raise NucleiAdapterError(
            f"template dir missing: {base}. "
            "See docs/nuclei-template-intake.md §2 for install."
        )
    actual = _compute_templates_hash(base)
    if actual != NUCLEI_TEMPLATES_HASH:
        raise NucleiAdapterError(
            f"template dir hash mismatch: expected "
            f"{NUCLEI_TEMPLATES_HASH[:16]}..., got {actual[:16]}... "
            "Templates changed on disk — re-review per "
            "docs/nuclei-template-intake.md §6."
        )


def run_nuclei(
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
) -> NucleiRunResult:
    db_obj, owns = coerce_db(db)
    run_id = uuid.uuid4().hex[:16]
    home_dir = Path(f"/tmp/sentinel-nuclei-home-{run_id}")
    try:
        approval = ApprovalStore(db_obj).get(approval_id)
        if approval is None:
            raise NucleiAdapterError(f"approval {approval_id!r} not found")
        if approval.revoked_at_utc:
            raise NucleiAdapterError(f"approval {approval_id!r} revoked")

        _verify_templates_dir()

        manifest = ManifestStore(db_obj).get_by_tool_version(
            NUCLEI_TOOL_NAME, NUCLEI_VERSION,
        )
        if manifest is None:
            raise NucleiAdapterError(
                f"no manifest for nuclei {NUCLEI_VERSION} — register first"
            )
        if not manifest.manifest.network_access:
            raise NucleiAdapterError(
                "nuclei manifest must be network_access=True"
            )

        # Nuclei writes ~/.config/nuclei, ~/.cache/nuclei, ~/.pdcp at start.
        # `nobody` cannot write to the operator's home directory. Redirect HOME
        # to a per-run /tmp dir. Pre-create subdirs 0777 so
        # cleanup with shutil.rmtree can unlink files `nobody` created.
        for d in (
            home_dir,
            home_dir / ".config",
            home_dir / ".config" / "nuclei",
            home_dir / ".cache",
            home_dir / ".cache" / "nuclei",
            home_dir / ".pdcp",
        ):
            d.mkdir(parents=True, exist_ok=True)
            prepare_sandbox_dir(d)

        rate = max(1, min(int(approval.request_rate_budget), 100))
        params = {
            "hostname": target_hostname,
            "port": port,
            "scheme": scheme,
            "rate_limit": rate,
            "timeout_seconds": timeout_seconds,
        }
        argv = build_argv_for_profile(
            profile_name="nuclei/scan",
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
            estimated_requests=max(50, rate * 10),
            estimated_output_bytes=100000,
            operation_profile="nuclei/scan",
            profile_params=params,
            env_overrides={"HOME": str(home_dir)},
        )

        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=NUCLEI_TOOL_NAME,
            adapter_version=NUCLEI_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        findings = parse_output(result.stdout or "")

        evidence = ingest_evidence(
            db_obj, engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"nuclei_{target_hostname}_{port}.jsonl",
            content_type="application/x-ndjson",
            content=(result.stdout or "").encode("utf-8"),
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
            event_type="nuclei_run",
            decision="ok" if result.exit_code == 0 else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "target": f"{target_hostname}:{port}",
                "findings_count": len(findings),
                "rate_limit": rate,
                "evidence_id": evidence.evidence_id,
            },
        )

        return NucleiRunResult(
            findings=findings,
            findings_count=len(findings),
            evidence=evidence,
            process_exit_code=result.exit_code,
            execution_status=result.execution_status,
        )
    finally:
        shutil.rmtree(home_dir, ignore_errors=True)
        if owns:
            db_obj.close()
