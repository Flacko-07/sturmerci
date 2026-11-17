# SPDX-License-Identifier: Apache-2.0
"""Subfinder adapter — first network-capable adapter (M5.2c).

Uses SandboxRunner (M5.1/M5.2b) with provider_endpoints=("crt.sh",).
The only sanctioned source is crt.sh: declared in the manifest,
required to be authorized by the approval, and requested by this adapter.
Any of the three missing = SandboxDenied before spawn.

Writes discovered subdomains to candidate_assets. Never to
approved_assets — the operator promotes explicitly.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from sentinel.assets.store import AssetStore
from sentinel.runner.sandbox_runner import (
    SandboxDenied,
    SandboxRequest,
    SandboxResult,
    run_in_sandbox,
)
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


SUBFINDER_TOOL_NAME = "subfinder"
SUBFINDER_VERSION = "2.6.7"
APPROVED_PROVIDERS: tuple[str, ...] = ("crt.sh",)

_VALID_HOSTNAME = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)


@dataclass(frozen=True, slots=True)
class SubfinderFinding:
    host: str
    input_domain: str
    source: str


@dataclass(frozen=True, slots=True)
class SubfinderRunResult:
    findings: list[SubfinderFinding]
    candidates_written: int
    candidates_skipped_invalid: int
    candidates_skipped_duplicate: int
    sandbox: SandboxResult
    execution_status: str = "COMPLETED"


def parse_output(stdout: str) -> list[SubfinderFinding]:
    """Parse Subfinder's -json -silent output (one JSON object per line).

    Lines that fail to parse, are not dicts, or lack a 'host' field are
    skipped. A malformed line from a passive source is noise, not a
    security event — the security checks are in validate_result_host.
    """
    findings: list[SubfinderFinding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        host = obj.get("host")
        if not isinstance(host, str) or not host:
            continue
        findings.append(
            SubfinderFinding(
                host=host,
                input_domain=str(obj.get("input") or ""),
                source=str(obj.get("source") or "unknown"),
            )
        )
    return findings


def validate_result_host(host: str, target_domain: str) -> tuple[bool, str | None]:
    """Return (is_valid, reason_if_invalid).

    Valid = DNS hostname, no wildcards, ends in .<target> or equals target.
    The apex is accepted (it appears in certs), but operators typically
    only promote true subdomains.
    """
    host_l = host.lower().rstrip(".")
    target_l = target_domain.lower().rstrip(".")
    if "*" in host_l:
        return False, "wildcard"
    if not _VALID_HOSTNAME.match(host_l):
        return False, "invalid_hostname"
    if host_l != target_l and not host_l.endswith("." + target_l):
        return False, f"not_subdomain_of_{target_l}"
    return True, None


def run_subfinder(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_domain: str,
    engagements_root: Path,
    actor: str = "operator",
    timeout_seconds: int = 180,
) -> SubfinderRunResult:
    """Run pinned Subfinder via SandboxRunner, parse output, write candidates.

    Preconditions enforced by SandboxRunner (before any subprocess):
      - manifest registered, network-capable, hash-verified, binary digest ok
      - approval exists and belongs to this engagement
      - argv[0] matches manifest executable
      - target_domain is in approved_assets
      - gatekeeper allows (policy hash, scope lock, tool hashes, method/port)
      - provider nesting: request ⊆ approval ⊆ manifest
      - all resolved IPs (target + crt.sh) not in protected ranges

    Post-conditions:
      - every valid finding written to candidate_assets, deduped within run
        and against existing candidates for this engagement
      - invalid findings counted, not written
      - operator promotes explicitly later (never here)
    """
    db_obj, owns_db = coerce_db(db)
    try:
        manifest = ManifestStore(db_obj).get_by_tool_version(
            SUBFINDER_TOOL_NAME,
            SUBFINDER_VERSION,
        )
        if manifest is None:
            raise SandboxDenied(
                f"subfinder {SUBFINDER_VERSION} not registered — see "
                "docs/operator-guide.md for the registration script"
            )
        if not manifest.manifest.network_access:
            raise SandboxDenied(
                "subfinder manifest is not network-capable — "
                "adapter requires execution_class >= 2"
            )

        declared = set(manifest.manifest.infrastructure_endpoints)
        missing = set(APPROVED_PROVIDERS) - declared
        if missing:
            raise SandboxDenied(
                f"subfinder manifest does not declare "
                f"provider(s) {sorted(missing)}; adapter requires them"
            )

        argv = [
            manifest.manifest.executable_path,
            "-d",
            target_domain,
            "-sources",
            "crtsh",
            "-silent",
            "-json",
            "-nc",
        ]
        request = SandboxRequest(
            hostname=target_domain,
            port=443,
            protocol="https",
            method="GET",
            path="/",
            argv=argv,
            timeout_seconds=timeout_seconds,
            provider_endpoints=APPROVED_PROVIDERS,
            requires_target_connection=False,
            estimated_requests=len(APPROVED_PROVIDERS),
            estimated_output_bytes=20000,
            operation_profile="subfinder/passive_crtsh",
            profile_params={
                "domain": target_domain,
                # NOTE: "crtsh" is subfinder's internal source ID (what
                # `-sources` expects). "crt.sh" (APPROVED_PROVIDERS) is
                # the HTTPS hostname used for DNS resolution + provider
                # audit. Different namespaces, not a typo.
                "sources": ["crtsh"],
            },
        )

        sandbox_result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=SUBFINDER_TOOL_NAME,
            adapter_version=SUBFINDER_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        findings = parse_output(sandbox_result.stdout)

        seen: set[str] = set()
        invalid = 0
        duplicates = 0
        written = 0
        asset_store = AssetStore(db_obj)

        with db_obj.transaction() as conn:
            for f in findings:
                host_l = f.host.lower().rstrip(".")
                valid, _reason = validate_result_host(host_l, target_domain)
                if not valid:
                    invalid += 1
                    continue
                if host_l in seen:
                    duplicates += 1
                    continue
                seen.add(host_l)

                existing = conn.execute(
                    "SELECT 1 FROM candidate_assets "
                    "WHERE engagement_id = ? AND canonical_value = ?",
                    (engagement_id, host_l),
                ).fetchone()
                if existing:
                    duplicates += 1
                    continue

                asset_store.add_candidate(
                    engagement_id=engagement_id,
                    raw_value=f.host,
                    canonical_value=host_l,
                    asset_type="hostname",
                    discovery_source=f"subfinder:{f.source}",
                    discovery_metadata={
                        "execution_status": sandbox_result.execution_status,
                        "stdout_truncated": sandbox_result.truncated_stdout,
                        "stderr_truncated": sandbox_result.truncated_stderr,
                        "stdout_bytes": sandbox_result.stdout_bytes,
                        "stderr_bytes": sandbox_result.stderr_bytes,
                        "timed_out": sandbox_result.timed_out,
                        "terminated": sandbox_result.terminated,
                        "exit_code": sandbox_result.exit_code,
                        "output_limit_bytes": sandbox_result.output_limit_bytes,
                    },
                )
                written += 1

        return SubfinderRunResult(
            findings=findings,
            candidates_written=written,
            candidates_skipped_invalid=invalid,
            candidates_skipped_duplicate=duplicates,
            sandbox=sandbox_result,
            execution_status=sandbox_result.execution_status,
        )
    finally:
        if owns_db:
            db_obj.close()
