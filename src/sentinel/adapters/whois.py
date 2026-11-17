# SPDX-License-Identifier: Apache-2.0
"""WHOIS adapter — registration and administrative contact lookup (Class 1).

Queries the WHOIS server (port 43, RFC 3912) for a domain. The
server is a *provider* — the operator must authorize it per
engagement, same pattern as Subfinder/crt.sh. The target domain is
sent to the provider (this is disclosed metadata), so provider
authorization must include consent for that disclosure.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.runner.sandbox_runner import SandboxRequest, run_in_sandbox
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


WHOIS_TOOL_NAME = "whois"
WHOIS_VERSION = "5.5.21"  # adjust after apt install
PROFILE = "whois/target_lookup"

# Default whois server per TLD. The operator's approval must list the
# exact server they'll query — no implicit "any TLD goes to any server".
# For simplicity, this adapter requires the caller to specify the server
# explicitly. That forces the approval to be about a specific endpoint.
DEFAULT_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
}


class WhoisAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WhoisResult:
    domain: str
    server: str
    raw_response: str
    evidence: IngestResult
    execution_status: str = "COMPLETED"


def _server_for_tld(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower()
    return DEFAULT_SERVERS.get(tld)


def run_whois(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_domain: str,
    whois_server: str | None,
    engagements_root: Path,
    actor: str = "operator",
    timeout_seconds: int = 30,
) -> WhoisResult:
    """Query the WHOIS server for a domain via SandboxRunner.

    Requires:
      - engagement active
      - approval permitting the WHOIS server as a provider
      - target domain is an approved asset
    """
    db_obj, owns = coerce_db(db)
    try:
        # Resolve server from TLD if not given; refuse if unknown
        server = whois_server or _server_for_tld(target_domain)
        if not server:
            raise WhoisAdapterError(
                f"no default whois server for TLD of {target_domain!r}; "
                "specify --server and authorize it in the approval"
            )

        manifest = ManifestStore(db_obj).get_by_tool_version(
            WHOIS_TOOL_NAME,
            WHOIS_VERSION,
        )
        if manifest is None:
            raise WhoisAdapterError(
                f"no manifest for whois {WHOIS_VERSION} — register first"
            )

        request = SandboxRequest(
            hostname=server,
            scope_target=target_domain,
            port=43,
            protocol="whois",
            method="LOOKUP",
            path="/",
            argv=[
                manifest.manifest.executable_path,
                "--server",
                server,
                target_domain,
            ],
            timeout_seconds=timeout_seconds,
            additional_ports=(),
            provider_endpoints=(server,),
            provider_ports={server: 43},  # whois uses RFC 3912 port 43
            requires_target_connection=False,  # target domain is only a query argument
            estimated_requests=1,
            operation_profile="whois/target_lookup",
            profile_params={
                "target_domain": target_domain,
                "server": server,
            },
        )

        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=WHOIS_TOOL_NAME,
            adapter_version=WHOIS_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        evidence = ingest_evidence(
            db_obj,
            engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"whois_{target_domain}.txt",
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

        return WhoisResult(
            domain=target_domain,
            server=server,
            raw_response=result.stdout,
            evidence=evidence,
            execution_status=result.execution_status,
        )
    finally:
        if owns:
            db_obj.close()
