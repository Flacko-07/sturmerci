# SPDX-License-Identifier: Apache-2.0
"""dig adapter — DNS lookups against an approved resolver (Class 1).

The resolver (e.g. 1.1.1.1) is a *provider*. Querying it discloses
the target domain. Operator must authorize the resolver in the
engagement's approved_infrastructure_endpoints. The target domain
is a query argument; the sandbox never connects to it.

Forbidden flags prevent bypassing the resolver:
  +trace       -- queries root servers directly, bypassing approval
  -f           -- batch mode from a file, could query unrelated names
  +qr          -- debug output
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.runner.sandbox_runner import SandboxRequest, run_in_sandbox
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


DIG_TOOL_NAME = "dig"
DIG_VERSION = "9.18.39"
PROFILE = "dns_lookup"

ALLOWED_RECORD_TYPES = frozenset(
    {
        "A",
        "AAAA",
        "MX",
        "NS",
        "SOA",
        "TXT",
        "CNAME",
        "CAA",
        "SRV",
    }
)

FORBIDDEN_FLAGS = ("+trace", "-f", "+qr", "+tcp")  # +tcp refused to keep parsing simple


class DigAdapterError(ValueError):
    """dig adapter refused the request."""


@dataclass(frozen=True, slots=True)
class DnsRecord:
    name: str
    ttl: int
    record_class: str
    record_type: str
    value: str


@dataclass(frozen=True, slots=True)
class DigRunResult:
    domain: str
    resolver: str
    record_type: str
    records: list[DnsRecord]
    raw_response: str
    evidence: IngestResult
    execution_status: str = "COMPLETED"


def _validate_resolver(resolver: str) -> None:
    """Resolver must be a literal IP address. Hostnames refused."""
    try:
        ipaddress.ip_address(resolver)
    except ValueError as e:
        raise DigAdapterError(
            f"resolver must be an IP literal (e.g. 1.1.1.1); got {resolver!r}"
        ) from e


def _validate_domain(domain: str) -> None:
    if not domain or len(domain) > 253:
        raise DigAdapterError(f"invalid domain: {domain!r}")
    if "/" in domain or "@" in domain or " " in domain:
        raise DigAdapterError(f"domain contains forbidden characters: {domain!r}")


def parse_output(stdout: str, record_type: str) -> list[DnsRecord]:
    """Parse `dig +noall +answer` output.

    Format per line: <name> <ttl> <class> <type> <value>
    """
    records: list[DnsRecord] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        name, ttl_s, cls, rtype, value = parts
        try:
            ttl = int(ttl_s)
        except ValueError:
            continue
        if rtype != record_type:
            continue
        records.append(
            DnsRecord(
                name=name.rstrip("."),
                ttl=ttl,
                record_class=cls,
                record_type=rtype,
                value=value.rstrip("."),
            )
        )
    return records


def run_dig(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_domain: str,
    resolver_ip: str,
    engagements_root: Path,
    record_type: str = "A",
    actor: str = "operator",
    timeout_seconds: int = 30,
) -> DigRunResult:
    """Look up DNS records for target_domain via the approved resolver."""
    if record_type not in ALLOWED_RECORD_TYPES:
        raise DigAdapterError(
            f"record_type {record_type!r} not in {sorted(ALLOWED_RECORD_TYPES)}"
        )
    _validate_resolver(resolver_ip)
    _validate_domain(target_domain)

    db_obj, owns = coerce_db(db)
    try:
        manifest = ManifestStore(db_obj).get_by_tool_version(
            DIG_TOOL_NAME,
            DIG_VERSION,
        )
        if manifest is None:
            raise DigAdapterError(f"no manifest for dig {DIG_VERSION} — register first")
        if manifest.manifest.network_access is not True:
            raise DigAdapterError("dig manifest must be network_access=True")

        request = SandboxRequest(
            hostname=resolver_ip,
            scope_target=target_domain,
            port=53,
            protocol="dns",
            method="QUERY",
            path="/",
            argv=[
                manifest.manifest.executable_path,
                "+noall",
                "+answer",
                f"@{resolver_ip}",
                target_domain,
                record_type,
            ],
            timeout_seconds=timeout_seconds,
            additional_ports=(),
            provider_endpoints=(resolver_ip,),
            provider_ports={resolver_ip: 53},
            provider_protocols={resolver_ip: "udp"},
            requires_target_connection=False,
            estimated_requests=1,
            operation_profile="dig/dns_lookup",
            profile_params={
                "domain": target_domain,
                "resolver": resolver_ip,
                "record_type": record_type,
            },
        )

        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=DIG_TOOL_NAME,
            adapter_version=DIG_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        records = parse_output(result.stdout, record_type)
        evidence = ingest_evidence(
            db_obj,
            engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"dig_{target_domain}_{record_type}.txt",
            content_type="text/plain",
            content=result.stdout.encode("utf-8"),
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

        return DigRunResult(
            domain=target_domain,
            resolver=resolver_ip,
            record_type=record_type,
            records=records,
            raw_response=result.stdout,
            evidence=evidence,
            execution_status=result.execution_status,
        )
    finally:
        if owns:
            db_obj.close()
