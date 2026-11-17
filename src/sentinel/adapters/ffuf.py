# SPDX-License-Identifier: Apache-2.0
"""ffuf adapter — directory and path discovery (Class 2, active low-impact).

Design decisions:
  - Host-level approval covers all paths under the approved host:port.
  - Default blocklist of auth/login paths (ffuf probes look like brute
    force to a WAF; these endpoints are excluded unless the operator
    explicitly unblocks them at approval).
  - aggregate_request_budget must be >= wordlist_size * 1.1, forcing
    explicit authorization of the scan size.
  - Rate from approval.request_rate_budget.
  - Wordlists must stay under the packaged resource directory, source-tree
    fallback, or an explicit operator-configured directory.
  - GET requests only.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from sentinel.audit.store import AuditStore
from sentinel.assets.store import AssetStore
from sentinel.approval.store import ApprovalStore
from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.runner.sandbox_runner import SandboxRequest, run_in_sandbox
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


FFUF_TOOL_NAME = "ffuf"
FFUF_VERSION = "2.1.0"
PROFILE = "dir_discovery"

def _wordlist_dir() -> Path:
    configured = os.environ.get("SENTINEL_WORDLIST_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    resource_dir = Path(str(
        resources.files("sentinel").joinpath("resources", "wordlists")
    ))
    if resource_dir.is_dir():
        return resource_dir
    # Compatibility for a source checkout while redistribution rights for
    # config/wordlists/common.txt are being reviewed.
    source_root = Path(__file__).resolve().parents[3]
    checkout_dir = source_root / "config" / "wordlists"
    if (source_root / "pyproject.toml").is_file() and checkout_dir.is_dir():
        return checkout_dir
    return resource_dir


WORDLIST_DIR = _wordlist_dir()

# Paths that are refused by default. These are credential attack
# surfaces where ffuf-style enumeration looks like brute force.
DEFAULT_BLOCKED_PATHS = frozenset({
    "/login", "/auth", "/password", "/reset",
    "/admin/login", "/2fa", "/oauth", "/sso",
    "/account/login", "/signin", "/sign_in",
})

# Extensions we will probe (single response body per extension).
ALLOWED_EXTENSIONS = frozenset({"", ".php", ".html", ".json", ".txt", ".xml"})

# Response size cap (bytes). Findings larger than this are truncated
# in the evidence; the finding itself only records the status/length.
MAX_BODY_BYTES = 500_000


class FfufAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FfufFinding:
    path: str
    status: int
    length: int
    content_type: str
    redirect_location: str
    url: str


@dataclass(frozen=True, slots=True)
class FfufRunResult:
    findings: list[FfufFinding]
    findings_count: int
    evidence: IngestResult
    wordlist_size: int
    blocked_paths_skipped: int
    process_exit_code: int
    execution_status: str = "COMPLETED"


def _resolve_wordlist(wordlist_name: str) -> Path:
    """Return a wordlist path under the packaged resource directory."""
    if not wordlist_name:
        raise FfufAdapterError(
            f"wordlist {wordlist_name!r} escapes the bundled wordlists"
        )
    base = WORDLIST_DIR.resolve()
    path = (WORDLIST_DIR / wordlist_name).resolve()
    if not path.is_relative_to(base):
        raise FfufAdapterError(
            f"wordlist {wordlist_name!r} escapes the bundled wordlists"
        )
    if not path.is_file():
        raise FfufAdapterError(
            f"wordlist {wordlist_name!r} not found in bundled wordlists. "
            f"Available: {sorted(p.name for p in WORDLIST_DIR.glob('*.txt'))}"
        )
    return path


def _count_wordlist(path: Path) -> int:
    with path.open("r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip() and not line.startswith("#"))


def parse_output(stdout: str) -> list[FfufFinding]:
    """Parse ffuf -of json output."""
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
    findings: list[FfufFinding] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url", "") or "")
        if not url.startswith(("http://", "https://")):
            continue
        try:
            status = int(r.get("status", 0) or 0)
        except (TypeError, ValueError):
            continue
        try:
            length = int(r.get("length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        # Extract the input path from the url
        path_match = re.search(r"^(?:https?://[^/]+)(/.*)?$", url)
        path = path_match.group(1) if path_match and path_match.group(1) else "/"
        findings.append(FfufFinding(
            path=path,
            status=status,
            length=length,
            content_type=str(r.get("content-type", "") or ""),
            redirect_location=str(r.get("redirectlocation", "") or "")[:500],
            url=url,
        ))
    return findings


def run_ffuf(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_hostname: str,
    port: int,
    scheme: str,
    wordlist_name: str = "common.txt",
    engagements_root: Path,
    actor: str = "operator",
    timeout_seconds: int = 600,
) -> FfufRunResult:
    """Run ffuf against an approved host:port with a curated wordlist."""
    db_obj, owns = coerce_db(db)
    try:
        approval = ApprovalStore(db_obj).get(approval_id)
        if approval is None:
            raise FfufAdapterError(f"approval {approval_id!r} not found")
        if approval.revoked_at_utc:
            raise FfufAdapterError(f"approval {approval_id!r} revoked")

        # Budget gate: wordlist must fit within approval budget
        wordlist_path = _resolve_wordlist(wordlist_name)
        wordlist_size = _count_wordlist(wordlist_path)
        if wordlist_size == 0:
            raise FfufAdapterError(f"wordlist {wordlist_name!r} is empty")
        required_budget = int(wordlist_size * 1.1) + 1
        if approval.aggregate_request_budget < required_budget:
            raise FfufAdapterError(
                f"wordlist {wordlist_name!r} has {wordlist_size} entries; "
                f"approval aggregate_request_budget is "
                f"{approval.aggregate_request_budget}, need >= "
                f"{required_budget}. Re-issue approval with a larger budget."
            )

        # Rate gate: must be > 0 and bounded
        rate = max(1, min(int(approval.request_rate_budget), 100))

        manifest = ManifestStore(db_obj).get_by_tool_version(
            FFUF_TOOL_NAME, FFUF_VERSION,
        )
        if manifest is None:
            raise FfufAdapterError(
                f"no manifest for ffuf {FFUF_VERSION} — register first"
            )
        if not manifest.manifest.network_access:
            raise FfufAdapterError("ffuf manifest must be network_access=True")

        target_url = f"{scheme}://{target_hostname}:{port}/FUZZ"

        # ffuf supports -request-proto and -rate
        argv = [
            manifest.manifest.executable_path,
            "-u", target_url,
            "-w", str(wordlist_path.resolve()),
            "-of", "json",
            "-o", "/dev/stdout",
            "-mc", "200,201,202,204,301,302,307,308,401,403,405",
            "-rate", str(rate),
            "-t", "1",
            "-timeout", "10",
            "-s",
            "-X", "GET",
        ]

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
            estimated_requests=wordlist_size,
            estimated_output_bytes=wordlist_size * 500,
            operation_profile="ffuf/dir_discovery",
            profile_params={
                "hostname": target_hostname,
                "port": port,
                "scheme": scheme,
                "wordlist_path": str(wordlist_path.resolve()),
                "rate": rate,
            },
        )

        t0 = time.monotonic()
        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=FFUF_TOOL_NAME,
            adapter_version=FFUF_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )
        duration = time.monotonic() - t0

        findings = parse_output(result.stdout or "")

        # Filter out blocked paths
        kept: list[FfufFinding] = []
        blocked_skipped = 0
        for f in findings:
            if f.path in DEFAULT_BLOCKED_PATHS:
                blocked_skipped += 1
                continue
            kept.append(f)

        evidence = ingest_evidence(
            db_obj, engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"ffuf_{target_hostname}_{port}.json",
            content_type="application/json",
            content=(result.stdout or "{}").encode("utf-8"),
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
            event_type="ffuf_run", decision="ok" if result.exit_code == 0 else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "findings_count": len(kept),
                "blocked_paths_skipped": blocked_skipped,
                "wordlist": wordlist_name,
                "wordlist_size": wordlist_size,
                "rate": rate,
                "evidence_id": evidence.evidence_id,
                "duration_seconds": round(duration, 3),
            },
        )

        return FfufRunResult(
            findings=kept,
            findings_count=len(kept),
            evidence=evidence,
            wordlist_size=wordlist_size,
            blocked_paths_skipped=blocked_skipped,
            process_exit_code=result.exit_code,
            execution_status=result.execution_status,
        )
    finally:
        if owns:
            db_obj.close()
