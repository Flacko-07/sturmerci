# SPDX-License-Identifier: Apache-2.0
"""theHarvester adapter — passive OSINT discovery (Class 1).

Queries external providers about a domain. Does NOT connect to the
target — only to providers (crt.sh, otx, rapiddns). Runs in the sandbox
with per-run writable HOME and cwd (both needed because theHarvester
writes to ~/.theHarvester on startup).

Writes to /tmp/sentinel-harv-<uuid>/harvester.json (via the -f flag);
adapter reads it after subprocess and ingests as evidence.

Provider allowlist: crtsh, otx, rapiddns. Each provider MUST be on the
approval's approved_infrastructure_endpoints.
"""
from __future__ import annotations

import json
import os
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


THEHARVESTER_TOOL_NAME = "theHarvester"
THEHARVESTER_VERSION = "4.6.0"
PROFILE = "passive_discovery"

ALLOWED_PROVIDERS = frozenset({"crtsh", "otx", "rapiddns"})

# (batch B) theHarvester uses internal source IDs (crtsh, otx, rapiddns)
# that are NOT hostnames. The manifest and approval declare HOSTNAMES the
# sandbox will actually connect to. This maps source ID -> exact HTTPS
# endpoint the tool queries.
SOURCE_TO_HOST = {
    "crtsh": "crt.sh",
    "otx": "otx.alienvault.com",
    "rapiddns": "rapiddns.io",
}

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,63}$"
)


class TheHarvesterAdapterError(ValueError):
    """theHarvester adapter refused the request."""


@dataclass(frozen=True, slots=True)
class TheHarvesterFinding:
    hostname: str


@dataclass(frozen=True, slots=True)
class TheHarvesterRunResult:
    findings: list[TheHarvesterFinding]
    findings_count: int
    evidence: IngestResult
    providers_used: tuple[str, ...]
    process_exit_code: int
    execution_status: str = "COMPLETED"


def parse_output(text: str) -> list[TheHarvesterFinding]:
    """Parse theHarvester's JSON host list.

    Format: {"hosts": ["api.example.com", "www.example.com:1.2.3.4", ...]}
    Some entries have :ip suffix; strip it. Reject non-FQDN entries.
    """
    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    hosts = data.get("hosts")
    if not isinstance(hosts, list):
        return []
    out: list[TheHarvesterFinding] = []
    seen: set[str] = set()
    for h in hosts:
        if not isinstance(h, str) or not h:
            continue
        host = h.split(":", 1)[0].strip().lower()
        if host in seen:
            continue
        if not _HOSTNAME_RE.match(host):
            continue
        seen.add(host)
        out.append(TheHarvesterFinding(hostname=host))
    return out


def _validate_domain(domain: str) -> None:
    if not domain:
        raise TheHarvesterAdapterError(f"invalid domain: {domain!r}")
    # Check the local-block FIRST — "localhost" and "127.0.0.1" don't
    # match the FQDN regex (no dot / numeric TLD), so if the regex runs
    # first they fall through as "invalid domain" and the more specific
    # refusal message is unreachable.
    if domain.endswith(".local") or domain in ("localhost", "127.0.0.1"):
        raise TheHarvesterAdapterError(f"refusing local domain: {domain!r}")
    if not _HOSTNAME_RE.match(domain):
        raise TheHarvesterAdapterError(f"invalid domain: {domain!r}")


def run_theharvester(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_domain: str,
    engagements_root: Path,
    providers: tuple[str, ...] = ("crtsh", "otx", "rapiddns"),
    limit: int = 500,
    actor: str = "operator",
    timeout_seconds: int = 300,
) -> TheHarvesterRunResult:
    """Run theHarvester passive discovery against an approved domain."""
    db_obj, owns = coerce_db(db)
    run_id = uuid.uuid4().hex[:16]
    run_dir = Path(f"/tmp/sentinel-harv-{run_id}")
    home_dir = run_dir / "home"
    out_base = str(run_dir / "harvester")
    out_json = Path(f"{out_base}.json")
    try:
        approval = ApprovalStore(db_obj).get(approval_id)
        if approval is None:
            raise TheHarvesterAdapterError(f"approval {approval_id!r} not found")
        if approval.revoked_at_utc:
            raise TheHarvesterAdapterError(f"approval {approval_id!r} revoked")

        _validate_domain(target_domain)

        if not isinstance(providers, tuple) or not providers:
            raise TheHarvesterAdapterError("providers must be a non-empty tuple")
        bad = set(providers) - ALLOWED_PROVIDERS
        if bad:
            raise TheHarvesterAdapterError(
                f"providers {sorted(bad)} not in allowlist {sorted(ALLOWED_PROVIDERS)}"
            )
        if not (1 <= int(limit) <= 5000):
            raise TheHarvesterAdapterError(f"limit out of range: {limit!r}")

        manifest = ManifestStore(db_obj).get_by_tool_version(
            THEHARVESTER_TOOL_NAME, THEHARVESTER_VERSION,
        )
        if manifest is None:
            raise TheHarvesterAdapterError(
                f"no manifest for {THEHARVESTER_TOOL_NAME} {THEHARVESTER_VERSION}"
            )
        if not manifest.manifest.network_access:
            raise TheHarvesterAdapterError(
                "theHarvester manifest must be network_access=True"
            )

        # Per-run dirs: world-writable so `nobody` can write; readable
        # afterwards so the adapter can read the JSON the tool writes.
        run_dir.mkdir(parents=True, exist_ok=True)
        prepare_sandbox_dir(run_dir)
        home_dir.mkdir(exist_ok=True)
        prepare_sandbox_dir(home_dir)
        cfg_dir = home_dir / ".theHarvester"
        cfg_dir.mkdir(exist_ok=True)
        prepare_sandbox_dir(cfg_dir)

        params = {
            "domain": target_domain,
            "sources": list(providers),
            "limit": int(limit),
            "out_base": out_base,
        }
        argv = build_argv_for_profile(
            profile_name="theharvester/passive_discovery",
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
            # (batch B) Map source IDs -> hostnames for provider nesting.
            provider_endpoints=tuple(SOURCE_TO_HOST[p] for p in providers),
            provider_ports={SOURCE_TO_HOST[p]: 443 for p in providers},
            requires_target_connection=False,  # only queries providers
            estimated_requests=max(len(providers) * 2, 4),
            estimated_output_bytes=50000,
            operation_profile="theharvester/passive_discovery",
            profile_params=params,
            env_overrides={"HOME": str(home_dir)},
            cwd=str(run_dir),
        )

        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=THEHARVESTER_TOOL_NAME,
            adapter_version=THEHARVESTER_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        # Read JSON the tool wrote (if any)
        if out_json.is_file():
            try:
                content = out_json.read_bytes()
            except OSError:
                content = b'{"hosts": []}'
        else:
            content = b'{"hosts": []}'

        findings = parse_output(content.decode("utf-8", errors="replace"))

        evidence = ingest_evidence(
            db_obj, engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"theharvester_{target_domain}.json",
            content_type="application/json",
            content=content,
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
            event_type="theharvester_run",
            decision="ok" if result.exit_code in (0, 1) else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "domain": target_domain,
                "providers": list(providers),
                "findings_count": len(findings),
                "evidence_id": evidence.evidence_id,
                "process_exit_code": result.exit_code,
            },
        )

        return TheHarvesterRunResult(
            findings=findings,
            findings_count=len(findings),
            evidence=evidence,
            providers_used=providers,
            process_exit_code=result.exit_code,
            execution_status=result.execution_status,
        )
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
        if owns:
            db_obj.close()
