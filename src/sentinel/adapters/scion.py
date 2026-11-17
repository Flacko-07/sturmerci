# SPDX-License-Identifier: Apache-2.0
"""scion adapter — passive subdomain discovery (Class 1).

scion is a Go binary, statically linked, no writable HOME, no config
files. Free keyless sources: crt.sh, Certspotter, HackerTarget,
Wayback, RapidDNS, AlienVault OTX. Key-gated sources (VirusTotal,
Shodan, etc.) are silently skipped when env vars are unset.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sentinel.audit.store import AuditStore
from sentinel.approval.store import ApprovalStore
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.runner.profiles import build_argv_for_profile
from sentinel.runner.sandbox_runner import SandboxRequest, run_in_sandbox
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


SCION_TOOL_NAME = "scion"
SCION_VERSION = "0.1.2"
PROFILE = "passive_discovery"

# (batch B) Scion queries these hostnames on every run with --subs-only.
# Each entry must appear in:
#   1. The manifest's infrastructure_endpoints
#   2. The approval's approved_infrastructure_endpoints
#   3. This SandboxRequest's provider_endpoints (below)
# If any entry is missing from any of the three, SandboxRunner refuses
# the run before spawning scion.
SCION_FREE_PROVIDERS = (
    "crt.sh",                  # Certificate Transparency aggregator
    "api.certspotter.com",     # Cert Spotter API
    "api.hackertarget.com",    # HackerTarget hostsearch
    "web.archive.org",         # Wayback Machine CDX
    "rapiddns.io",             # RapidDNS
    "otx.alienvault.com",      # AlienVault OTX passive DNS
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,63}$"
)


class ScionAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ScionFinding:
    hostname: str


@dataclass(frozen=True, slots=True)
class ScionRunResult:
    findings: list[ScionFinding]
    findings_count: int
    evidence: IngestResult
    process_exit_code: int
    execution_status: str = "COMPLETED"


def parse_output(stdout: str) -> list[ScionFinding]:
    if not stdout:
        return []
    out: list[ScionFinding] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        host = line.strip()
        if not host or host in seen:
            continue
        if not _HOSTNAME_RE.match(host):
            continue
        seen.add(host)
        out.append(ScionFinding(hostname=host))
    return out


def _validate_domain(domain: str) -> None:
    if not domain:
        raise ScionAdapterError(f"invalid domain: {domain!r}")
    # Check the local-host block FIRST — "localhost" and "127.0.0.1"
    # don't match the FQDN regex (no dot / numeric TLD), so if the regex
    # runs first they fall through as "invalid domain" and the more
    # specific refusal message is unreachable.
    if domain.endswith(".local") or domain in ("localhost", "127.0.0.1"):
        raise ScionAdapterError(f"refusing local domain: {domain!r}")
    if not _HOSTNAME_RE.match(domain):
        raise ScionAdapterError(f"invalid domain: {domain!r}")


def run_scion(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_domain: str,
    engagements_root: Path,
    actor: str = "operator",
    timeout_seconds: int = 300,
) -> ScionRunResult:
    db_obj, owns = coerce_db(db)
    try:
        approval = ApprovalStore(db_obj).get(approval_id)
        if approval is None:
            raise ScionAdapterError(f"approval {approval_id!r} not found")
        if approval.revoked_at_utc:
            raise ScionAdapterError(f"approval {approval_id!r} revoked")

        _validate_domain(target_domain)

        manifest = ManifestStore(db_obj).get_by_tool_version(
            SCION_TOOL_NAME, SCION_VERSION,
        )
        if manifest is None:
            raise ScionAdapterError(
                f"no manifest for scion {SCION_VERSION} — register first"
            )
        if not manifest.manifest.network_access:
            raise ScionAdapterError("scion manifest must be network_access=True")

        params = {"domain": target_domain}
        argv = build_argv_for_profile(
            profile_name="scion/passive_discovery",
            executable_path=manifest.manifest.executable_path,
            params=params,
        )

        request = SandboxRequest(
            hostname=target_domain,
            port=443,
            protocol="https",
            method="GET",
            path="/",
            argv=argv,
            timeout_seconds=timeout_seconds,
            additional_ports=(),
            provider_endpoints=SCION_FREE_PROVIDERS,
            provider_ports={p: 443 for p in SCION_FREE_PROVIDERS},
            requires_target_connection=False,
            estimated_requests=10,
            estimated_output_bytes=10000,
            operation_profile="scion/passive_discovery",
            profile_params=params,
        )

        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=SCION_TOOL_NAME,
            adapter_version=SCION_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        findings = parse_output(result.stdout or "")

        evidence = ingest_evidence(
            db_obj, engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"scion_{target_domain}.txt",
            content_type="text/plain",
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
            event_type="scion_run",
            decision="ok" if result.exit_code == 0 else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "domain": target_domain,
                "findings_count": len(findings),
                "evidence_id": evidence.evidence_id,
            },
        )

        return ScionRunResult(
            findings=findings,
            findings_count=len(findings),
            evidence=evidence,
            process_exit_code=result.exit_code,
            execution_status=result.execution_status,
        )
    finally:
        if owns:
            db_obj.close()
