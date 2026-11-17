# SPDX-License-Identifier: Apache-2.0
"""httpx inventory adapter (M7.1).

Sends a single HTTP GET or HEAD to an approved hostname:port at path `/`,
parses the resulting JSONL, writes inventory observations to
`candidate_assets` with asset_type='web_endpoint'.

Path-restricted scopes, redirects, custom headers, and non-GET/HEAD
methods are refused. See docs/m7-web-inventory-design.md for the
L7-gap rationale.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.assets.store import AssetStore
from sentinel.runner.sandbox_runner import (
    SandboxDenied, SandboxRequest, SandboxResult, run_in_sandbox,
)
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


HTTPX_TOOL_NAME = "httpx"
HTTPX_VERSION = "1.6.10"
PROFILE = "inventory"

ALLOWED_METHODS = ("GET", "HEAD")
ALLOWED_SCHEMES = ("https", "http")

FORBIDDEN_FLAGS = (
    "-path", "-paths", "-p",            # path scope
    "-follow-redirects", "-fr",         # redirects escape approval
    "-H", "-header",                    # arbitrary headers
    "-body",                            # request body
    # NOTE: -x IS allowed -- it carries the method (GET or HEAD, validated
    # by build_argv before this check runs). -X (capital) and -method are
    # both forbidden so a caller cannot smuggle an alternate method flag
    # past the profile builder. See M7-P0-E.
    "-X",
    "-method",
    "-http-proxy", "-proxy",            # proxy
    "-websocket", "-ws",                # ws upgrade
    "-auth",                            # auth injection
    "-dc", "-dashboard",                # external dashboard = provider
    "-sr", "-store-response",           # filesystem writes outside artifacts
    "-screenshot", "-ss",               # chromedriver side channel
)

# Hostname pattern: letters/digits/hyphen labels, dots, no wildcards.
_VALID_HOSTNAME = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class HttpxAdapterError(ValueError):
    """Refused by the adapter (independent of sandbox denial)."""


@dataclass(frozen=True, slots=True)
class WebEndpointObservation:
    url: str
    input_url: str
    port: int
    scheme: str
    status_code: int | None
    title: str
    webserver: str
    tech: tuple[str, ...]
    tls_subject_cn: str
    tls_issuer: str
    tls_dns_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HttpxRunResult:
    findings: list[WebEndpointObservation]
    endpoints_written: int
    skipped_invalid: int
    skipped_duplicate: int
    sandbox: SandboxResult
    execution_status: str = "COMPLETED"


def _assert_no_forbidden_flags(argv: list[str]) -> None:
    for a in argv:
        for forbidden in FORBIDDEN_FLAGS:
            if a == forbidden or a.startswith(forbidden + "="):
                raise HttpxAdapterError(
                    f"forbidden httpx flag in argv: {a!r} "
                    "(path, redirects, headers, body, method override, "
                    "proxy, auth, dashboard, or external writes)"
                )


def build_argv(
    executable_path: str,
    hostname: str,
    port: int,
    scheme: str,
    method: str,
) -> list[str]:
    """Construct httpx argv for a single inventory probe."""
    if not _VALID_HOSTNAME.match(hostname.lower()):
        raise HttpxAdapterError(f"invalid hostname: {hostname!r}")
    if not (1 <= port <= 65535):
        raise HttpxAdapterError(f"invalid port: {port!r}")
    if scheme not in ALLOWED_SCHEMES:
        raise HttpxAdapterError(
            f"scheme {scheme!r} not in {ALLOWED_SCHEMES}"
        )
    if method not in ALLOWED_METHODS:
        raise HttpxAdapterError(
            f"method {method!r} not in {ALLOWED_METHODS}"
        )

    url = f"{scheme}://{hostname}:{port}/"
    # -x <METHOD> is required so the adapter's argv matches what the
    # operation profile produces (M6-P0-A enforcement). This also fixes
    # M7-P0-E: without it, the binary always sent GET even when the
    # approval authorized HEAD.
    argv = [
        executable_path,
        "-u", url,
        "-x", method,
        "-silent",
        "-json",
        "-nc",
        "-duc",  # disable update check = no vendor telemetry
    ]
    _assert_no_forbidden_flags(argv)
    return argv


def parse_output(jsonl: str) -> list[WebEndpointObservation]:
    """Parse httpx -json JSONL output. Malformed lines skipped."""
    findings: list[WebEndpointObservation] = []
    if not jsonl:
        return findings
    for line in jsonl.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        url = obj.get("url")
        if not isinstance(url, str) or not url:
            continue
        tls = obj.get("tls") if isinstance(obj.get("tls"), dict) else {}
        tech = obj.get("tech") if isinstance(obj.get("tech"), list) else []
        dns_names = tls.get("dns_names") if isinstance(tls.get("dns_names"), list) else []
        status = obj.get("status_code") or obj.get("status-code")
        if isinstance(status, str):
            try:
                status = int(status)
            except ValueError:
                status = None
        # M7-03: strict port parsing. A non-numeric port in the tool
        # output is either malformed or hostile; skip the line rather
        # than crash the whole parse.
        try:
            port_val = int(obj.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not (0 <= port_val <= 65535):
            continue
        findings.append(WebEndpointObservation(
            url=url,
            input_url=str(obj.get("input") or ""),
            port=port_val,
            scheme=str(obj.get("scheme") or ""),
            status_code=status if isinstance(status, int) else None,
            title=str(obj.get("title") or ""),
            webserver=str(obj.get("webserver") or ""),
            tech=tuple(str(t) for t in tech),
            tls_subject_cn=str(tls.get("subject_cn") or ""),
            tls_issuer=str(tls.get("issuer_cn") or ""),
            tls_dns_names=tuple(str(n) for n in dns_names),
        ))
    return findings


def _validate_observation(
    obs: WebEndpointObservation,
    target_hostname: str,
    target_port: int,
    target_scheme: str,
) -> tuple[bool, str | None]:
    """Reject observations that don't match the approved target."""
    if obs.port != target_port:
        return False, f"port_mismatch_{obs.port}"
    if obs.scheme != target_scheme:
        return False, f"scheme_mismatch_{obs.scheme}"
    # Extract hostname from URL and compare
    m = re.match(rf"^{re.escape(target_scheme)}://([^/:]+):", obs.url)
    if not m:
        return False, "url_parse_fail"
    obs_host = m.group(1).lower()
    if obs_host != target_hostname.lower():
        return False, f"host_mismatch_{obs_host}"
    # M7-02: we only sent a request to /. If the observed URL reports
    # a different path, the tool followed a redirect or the response is
    # fabricated; either way it's out of scope for this inventory.
    rest = obs.url[len(m.group(0)):]  # everything after "scheme://host:"
    # Strip optional :port (already validated) then split off path
    if rest.startswith(str(target_port)):
        rest = rest[len(str(target_port)):]
    path_part = rest.split("?", 1)[0].split("#", 1)[0]
    if path_part not in ("", "/"):
        return False, f"path_mismatch_{path_part[:40]}"
    return True, None


def run_httpx(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_hostname: str,
    port: int = 443,
    scheme: str = "https",
    method: str = "GET",
    engagements_root: Path,
    actor: str = "operator",
    timeout_seconds: int = 60,
) -> HttpxRunResult:
    """Run pinned httpx inventory via SandboxRunner."""
    db_obj, owns_db = coerce_db(db)
    try:
        manifest = ManifestStore(db_obj).get_by_tool_version(
            HTTPX_TOOL_NAME, HTTPX_VERSION,
        )
        if manifest is None:
            raise SandboxDenied(
                f"httpx {HTTPX_VERSION} not registered — see operator guide"
            )
        if not manifest.manifest.network_access:
            raise SandboxDenied("httpx manifest is not network-capable")

        argv = build_argv(
            executable_path=manifest.manifest.executable_path,
            hostname=target_hostname,
            port=port,
            scheme=scheme,
            method=method,
        )

        # (P0.1) Route httpx through the profile builder so the runner
        # independently reconstructs argv and refuses mismatch. The
        # profile's builder must produce exactly the same argv as the
        # local build_argv() call above.
        _profile_params = {
            "hostname": target_hostname,
            "port": port,
            "scheme": scheme,
            "method": method,
        }

        request = SandboxRequest(
            hostname=target_hostname,
            port=port,
            protocol=scheme,
            method=method,
            path="/",
            argv=argv,
            timeout_seconds=timeout_seconds,
            additional_ports=(),
            provider_endpoints=(),          # httpx has no external providers
            requires_target_connection=True,
            estimated_requests=1,           # single target, single probe
            estimated_output_bytes=5000,
            operation_profile="httpx/inventory",
            profile_params=_profile_params,
        )

        sandbox_result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=HTTPX_TOOL_NAME,
            adapter_version=HTTPX_VERSION,
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
            for obs in findings:
                ok, _reason = _validate_observation(
                    obs, target_hostname, port, scheme,
                )
                if not ok:
                    invalid += 1
                    continue
                canonical = obs.url.rstrip("/") or obs.url
                if canonical in seen:
                    duplicates += 1
                    continue
                seen.add(canonical)

                existing = conn.execute(
                    "SELECT 1 FROM candidate_assets "
                    "WHERE engagement_id = ? AND canonical_value = ?",
                    (engagement_id, canonical),
                ).fetchone()
                if existing:
                    duplicates += 1
                    continue

                # M7-04: persist status code, tech, TLS metadata so
                # downstream triage/reporting has the full observation.
                metadata = {
                    "execution_status": sandbox_result.execution_status,
                    "stdout_truncated": sandbox_result.truncated_stdout,
                    "stderr_truncated": sandbox_result.truncated_stderr,
                    "stdout_bytes": sandbox_result.stdout_bytes,
                    "stderr_bytes": sandbox_result.stderr_bytes,
                    "timed_out": sandbox_result.timed_out,
                    "terminated": sandbox_result.terminated,
                    "exit_code": sandbox_result.exit_code,
                    "output_limit_bytes": sandbox_result.output_limit_bytes,
                    "status_code": obs.status_code,
                    "title": obs.title,
                    "webserver": obs.webserver,
                    "tech": list(obs.tech),
                    "tls_subject_cn": obs.tls_subject_cn,
                    "tls_issuer": obs.tls_issuer,
                    "tls_dns_names": list(obs.tls_dns_names),
                }
                asset_store.add_candidate(
                    engagement_id=engagement_id,
                    raw_value=obs.url,
                    canonical_value=canonical,
                    asset_type="web_endpoint",
                    discovery_source=f"httpx:{PROFILE}",
                    discovery_metadata=metadata,
                )
                written += 1

        return HttpxRunResult(
            findings=findings,
            endpoints_written=written,
            skipped_invalid=invalid,
            skipped_duplicate=duplicates,
            sandbox=sandbox_result,
            execution_status=sandbox_result.execution_status,
    )
    finally:
        if owns_db:
            db_obj.close()
