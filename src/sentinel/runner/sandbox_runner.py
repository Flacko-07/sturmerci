# SPDX-License-Identifier: Apache-2.0
"""SandboxRunner — the only permitted entry point for network-capable
subprocesses.

See docs/sandbox-runner-design.md for the design rationale.

Invariant (M5.1 / E-22):
    No network-capable subprocess may be launched outside
    sentinel.runner.sandbox_runner.run_in_sandbox.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import subprocess
import threading
from datetime import datetime, timezone
import time
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.approval.budget import (
    BudgetExhausted, check_available, reserve_budget, settle_budget,
)
from sentinel.approval.gatekeeper import RequestContext, check_request
from sentinel.l7.ca import L7CA
from sentinel.l7.gatekeeper_filter import make_gatekeeper_filter
from sentinel.l7.proxy import TLSProxy
from sentinel.runner import builtin_profiles as _builtin_profiles  # noqa: F401
from sentinel.runner.profiles import (
    ProfileError, argv_hash, build_argv_for_profile, get_profile,
)
from sentinel.approval.store import ApprovalStore
from sentinel.assets.store import AssetStore, target_asset_ids_hash
from sentinel.audit.store import AuditStore
from sentinel.engagement.store import EngagementStore
from sentinel.netns import nft as _nft
from sentinel.netns.namespace import (
    _kill_namespace_processes, run_namespace,
)
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


# (batch-4) Minimal environment allowlist for scanner processes. The
# parent process's full env is NOT inherited — that leaks HOME, shell
# history, credential-bearing vars, and vendor tokens (OPENAI_API_KEY,
# AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, etc.) into a sandboxed child that
# was supposed to be isolated. Adapters that need a specific var set it
# via env_overrides.
_MINIMAL_SCANNER_ENV_KEYS = frozenset({
    "PATH",
    "HOME",       # overridden per-run by env_overrides for nuclei/msf
    "TMPDIR",
    "LC_ALL",
    "LANG",
    "TZ",
})


class SandboxDenied(Exception):
    """Request refused by validation or gatekeeper — before execution."""


class SandboxError(Exception):
    """Runtime failure inside the sandbox (after the request was allowed)."""

    execution_status = "FAILED"


class _CappedTimeout(subprocess.TimeoutExpired):
    def __init__(self, timeout_s, output, stderr, stdout_truncated,
                 stderr_truncated):
        super().__init__("sandbox process", timeout_s, output=output, stderr=stderr)
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated


class SandboxTimeout(SandboxError):
    """Timed-out execution with bounded partial output metadata."""

    execution_status = "TIMED_OUT"

    def __init__(self, message: str, *, stdout_bytes: int = 0,
                 stderr_bytes: int = 0, stdout_truncated: bool = False,
                 stderr_truncated: bool = False, output_limit_bytes: int = 0):
        super().__init__(message)
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated
        self.output_limit_bytes = output_limit_bytes


class SandboxRevoked(SandboxError):
    """Approval revoked, expired, or engagement inactive mid-execution."""


@dataclass(frozen=True, slots=True)
class SandboxRequest:
    hostname: str
    port: int
    protocol: str
    method: str
    path: str
    argv: list[str]
    timeout_seconds: int = 60
    # Providers this specific run will contact (e.g. ("crt.sh",) for
    # Subfinder with -sources crtsh). Every entry must be in
    # approval.approved_infrastructure_endpoints AND in
    # manifest.infrastructure_endpoints. Empty = no providers, target only.
    provider_endpoints: tuple[str, ...] = ()
    # Per-provider port override. Default 443. Whois uses 43.
    provider_ports: dict[str, int] = field(default_factory=dict)
    # Additional ports to scan on the same hostname (Nmap scans multiple
    # ports per invocation). Each port is validated against the approval
    # individually, and each becomes its own approved destination IP:port
    # in the run namespace. `port` above is the primary and is used for
    # the RequestContext's representative port field.
    additional_ports: tuple[int, ...] = ()
    # When False, the target's IP:port is NOT added to the nftables approved
    # destinations. Use for adapters that only need to reach their
    # infrastructure providers (e.g. Subfinder needs crt.sh, not the target).
    # The hostname still resolves for dnsmasq; it just cannot be connected to.
    requires_target_connection: bool = True
    # Estimate of network probes this invocation will issue. Used for
    # aggregate_request_budget enforcement. Nmap sets this to len(ports);
    # Subfinder sets it to len(provider_endpoints). A higher estimate is
    # safer (budget is consumed faster); a lower one risks over-spend.
    estimated_requests: int = 1
    # (v4.1) Estimate of captured-output bytes this run will
    # produce. Used to reserve budget BEFORE execution — prior
    # version passed estimated_bytes=0 to check_available(), which
    # meant the budget could not refuse an over-run. Per-adapter
    # estimates populated by each adapter (default 0 = no
    # reservation, backwards-compatible).
    estimated_output_bytes: int = 0
    # Operation profile (M6-P0-A). The adapter declares a profile name +
    # typed params; the runner constructs the canonical argv from those.
    # argv is then verified byte-for-byte against the builder output --
    # if the caller sent something else, we refuse. This is the boundary
    # that makes "adapter rejects --script" a real guarantee: the runner
    # independently rejects it by calling the same builder.
    operation_profile: str | None = None
    profile_params: dict | None = None
    # Cap on captured stdout/stderr bytes per stream (M6-06). Excess is
    # drained but not retained. Default 1 MB is generous for JSON/XML
    # tool output; oversized output indicates misbehaviour.
    max_output_bytes: int = 1_000_000
    # When True, spawn an L7 TLS-terminating proxy in the main namespace,
    # route the tool through it via HTTPS_PROXY, install the run CA, and
    # do NOT approve the target IP directly. The scanner can reach the
    # proxy (10.99.0.1:proxy_port) and nothing else. Per-request L7
    # enforcement (method, path) happens in the proxy filter.
    use_tls_proxy: bool = False
    # CA bundle the proxy uses to verify the upstream fixture. None means
    # system CA bundle (production). Tests override this to point at a
    # locally-generated CA for the fixture HTTPS server.
    proxy_upstream_ca_bundle: Path | None = None
    # Extra environment variables for the scanner process. Needed for
    # tools (nuclei, theHarvester) that write to $HOME/.config or
    # $HOME/.cache; the sandbox drops to `nobody` whose default HOME
    # is unwritable. Set env_overrides={"HOME": "/tmp/..."} to redirect.
    env_overrides: dict[str, str] = field(default_factory=dict)
    # (batch-4) "minimal" (default): start from PATH/HOME/TMPDIR/
    # LC_ALL/LANG/TZ only, then merge env_overrides. "inherit":
    # legacy behaviour — copy the full parent env, then merge
    # env_overrides. Adapters that need an extra var should set
    # env_overrides, not switch to inherit.
    env_mode: str = "minimal"
    # (batch A) The asset the operation is *about*, checked against
    # approved_assets. Empty = same as hostname (backward compatible).
    # WHOIS/Dig set this to the target domain (the thing assessed) while
    # keeping hostname = network destination (server / resolver).
    scope_target: str = ""
    # (batch A) Protocol for the target connection. Default "tcp".
    target_protocol: str = "tcp"
    # (batch A) Per-provider protocol. Missing entries default to "tcp".
    # Dig sets {resolver_ip: "udp"} so the nft rule allows UDP/53.
    provider_protocols: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.env_mode not in ("minimal", "inherit"):
            raise ValueError(
                f"env_mode must be 'minimal' or 'inherit', "
                f"got {self.env_mode!r}"
            )
    # Working directory for the scanner process. None = inherit caller cwd.
    # IMPORTANT: some tools (msfconsole) run `pwd` at start and `cd` back
    # to it. If the caller was in a directory `nobody` cannot traverse
    # (e.g. /home/operator), the tool errors before doing anything. Adapters
    # whose tool does this MUST set cwd to a world-traversable dir.
    cwd: Path | None = None


@dataclass(frozen=True, slots=True)
class SandboxResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float
    namespace_name: str
    resolved_ip: str
    audit_event_seq: int | None
    used_providers: tuple[str, ...] = ()
    resolved_ips: tuple[str, ...] = ()
    proxy_port: int | None = None
    proxy_ca_path: Path | None = None
    # (v4.1) Output-cap truncation flags. Adapters MUST propagate these
    # to ingest_evidence(truncated_output=...) so the triage pipeline
    # refuses to treat an incomplete scan as complete. Prior version
    # returned only bytes; network adapters had no way to know.
    truncated_stdout: bool = False
    truncated_stderr: bool = False
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    timed_out: bool = False
    terminated: bool = False
    output_limit_bytes: int = 0

    @property
    def execution_status(self) -> str:
        """Categorical outcome shared by adapters and evidence records.

        (v4.3) Reviewer's finding: nmap/httpx/subfinder surface only
        'found N things', not 'was the scan complete'. A truncated scan
        reported as complete is a false negative with extra steps.

        Derived from existing fields — no schema change. `timed_out`
        is not a SandboxResult field; timeouts raise SandboxError from
        the runner, so callers get an exception rather than a result.
        Timeouts retain their bounded output and are separately labeled.
        """
        if self.timed_out:
            return "TIMED_OUT"
        if self.exit_code != 0 or self.terminated:
            return "FAILED"
        if self.truncated_stdout or self.truncated_stderr:
            return "PARTIAL"
        return "COMPLETED"


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve hostname to IPv4 addresses.

    IPv4-only by design: the nft ruleset uses `ip daddr` (IPv4), and
    hostname_records passed to dnsmasq must be A records only. IPv6
    would silently resolve but be blocked — confusing to debug. So we
    filter here.

    Tests monkeypatch this to simulate specific resolutions.
    """
    infos = socket.getaddrinfo(
        hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM
    )
    ips: list[str] = []
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips




# Re-exported from sentinel.approval.state so the L7 gatekeeper filter
# can share the same implementation without a circular import.
from sentinel.approval.state import (
    current_scope_lock_hash as _current_scope_lock_hash,
    current_policy_hash as _current_policy_hash,
)

def _current_adapter_code_sha256(adapter_code_path: Path) -> str:
    """SHA-256 of the adapter source file. Adapter edits invalidate
    approvals because the executable argv-builder could have changed."""
    if not adapter_code_path.is_file():
        raise SandboxDenied(
            f"adapter source not found: {adapter_code_path}"
        )
    return hashlib.sha256(adapter_code_path.read_bytes()).hexdigest()


def _current_egress_profile_id() -> str:
    """Identifier tied to the current egress policy configuration.

    Any change to the denied-ranges set or the table/chain names changes
    this value, invalidating existing approvals. The operator must
    re-approve after an egress-policy change.
    """
    payload = {
        "denied_ranges": sorted(_nft.DENIED_RANGES),
        "table": _nft.TABLE,
        "forward_chain": _nft.CHAIN,
        "input_chain": _nft.INPUT_CHAIN,
    }
    h = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    return f"egress_v1_{h}"


def _verify_provider_hash(approval) -> None:
    """Recompute the approved-providers hash and compare to the stored
    value. Catches DB tampering with either field.

    (batch A) Fail-closed: an approval that declares providers MUST
    carry a matching hash. Prior behaviour accepted an empty stored hash
    as "no provider binding", which meant a direct-DB-inserted approval
    could declare crt.sh with an empty hash and pass — the exact case
    fail-closed is supposed to catch.
    """
    from sentinel.approval.store import infrastructure_endpoints_hash
    if not approval.approved_infrastructure_endpoints:
        return  # no providers → no hash to verify
    stored = approval.approved_infrastructure_endpoints_hash or ""
    if not stored:
        raise SandboxDenied(
            "approval declares infrastructure providers but "
            "approved_infrastructure_endpoints_hash is empty — refusing "
            "fail-closed. Re-issue the approval through "
            "`sentinel approval issue` or set the hash to "
            "infrastructure_endpoints_hash(endpoints)."
        )
    expected = infrastructure_endpoints_hash(
        approval.approved_infrastructure_endpoints
    )
    if stored != expected:
        raise SandboxDenied(
            "approved infrastructure endpoints hash mismatch "
            "(approval may have been tampered with)"
        )


def _asset_id_for_hostname(
    db: Database, engagement_id: str, hostname: str
) -> str | None:
    row = db.connection.execute(
        "SELECT id FROM approved_assets "
        "WHERE engagement_id = ? AND canonical_value = ?",
        (engagement_id, hostname),
    ).fetchone()
    return row["id"] if row else None


def _verify_binary_digest(path: str, expected: str) -> None:
    p = Path(path)
    if not p.exists():
        raise SandboxDenied(f"adapter binary not found: {path}")
    actual = hashlib.sha256(p.read_bytes()).hexdigest()
    if actual != expected:
        raise SandboxDenied(
            f"adapter binary digest mismatch: expected {expected[:16]}... "
            f"got {actual[:16]}..."
        )


def _is_protected(ip: str) -> tuple[bool, str | None]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True, "invalid-ip"
    for rng in _nft.DENIED_RANGES:
        if addr in ipaddress.ip_network(rng):
            return True, rng
    return False, None


def _validate_provider_nesting(
    request_providers: tuple[str, ...],
    approved_providers: list[str],
    manifest_providers: tuple[str, ...],
) -> None:
    """Three-way nesting check for provider authorization.

    Requires:  request ⊆ approval ⊆ manifest
    Any request provider not in approval -> SandboxDenied.
    Any request provider not in manifest -> SandboxDenied (defense in depth
    against an approval that authorized something the tool isn't declared
    to contact, which would be a manifest-drift bug elsewhere).
    """
    approved_set = set(approved_providers)
    manifest_set = set(manifest_providers)
    for p in request_providers:
        if p not in approved_set:
            raise SandboxDenied(
                f"provider {p!r} not authorized for this engagement "
                f"(approved: {sorted(approved_set) or '[]'})"
            )
        if p not in manifest_set:
            raise SandboxDenied(
                f"provider {p!r} not declared by manifest "
                f"(declares: {sorted(manifest_set) or '[]'})"
            )


_AUDIT_DECISIONS = {
    "sandbox_start": "started",
    "sandbox_ok": "completed",
    "sandbox_provider_contact": "started",
    "sandbox_denied": "denied",
    "sandbox_error": "failed",
    "sandbox_timeout": "timed_out",
    "sandbox_revoked": "revoked",
}


def _capped_communicate(
    proc: subprocess.Popen,
    timeout_s: float,
    max_bytes: int,
) -> tuple[bytes, bytes, bool, bool]:
    """Read stdout/stderr from proc, truncating each to max_bytes.

    M6-06: subprocess.communicate() has no output cap; a misbehaving
    tool can produce unbounded output. This reader truncates at
    max_bytes per stream. We keep reading to EOF after truncation so
    the child doesn't block on a full pipe. Raises TimeoutExpired if
    proc doesn't exit within timeout_s.
    """
    if max_bytes <= 0:
        raise ValueError(f"max_bytes must be > 0, got {max_bytes}")
    out_buf = bytearray()
    err_buf = bytearray()
    out_trunc = [False]
    err_trunc = [False]

    def _reader(stream, buf, trunc_flag):
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                if len(buf) < max_bytes:
                    remaining = max_bytes - len(buf)
                    buf.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        trunc_flag[0] = True
                else:
                    # Drain silently to EOF so child doesn't block, but
                    # mark that we dropped bytes.
                    trunc_flag[0] = True
        except Exception:
            return

    t_out = threading.Thread(
        target=_reader, args=(proc.stdout, out_buf, out_trunc),
        daemon=True,
    )
    t_err = threading.Thread(
        target=_reader, args=(proc.stderr, err_buf, err_trunc),
        daemon=True,
    )
    t_out.start()
    t_err.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        t_out.join(timeout=5.0)
        t_err.join(timeout=5.0)
    if timed_out:
        raise _CappedTimeout(
            timeout_s, bytes(out_buf), bytes(err_buf),
            out_trunc[0], err_trunc[0],
        )
    return bytes(out_buf), bytes(err_buf), out_trunc[0], err_trunc[0]


def _audit(
    db: Database, engagement_id: str, actor: str, event_type: str,
    details: dict, *, fail_closed: bool = False,
) -> int | None:
    """Append an audit event.

    fail_closed=True: raise SandboxError if the write fails. Use for
    events that must precede a security-sensitive action (pre-spawn,
    provider contact). Audit failure must not silently permit execution.

    fail_closed=False (default): swallow and return None. Use for events
    that describe things that already happened (post-spawn success,
    denials where the request was already refused).
    """
    decision = _AUDIT_DECISIONS.get(event_type, "unknown")
    try:
        ev = AuditStore(db).append(
            engagement_id=engagement_id,
            actor=actor,
            event_type=event_type,
            decision=decision,
            details=details,
        )
        return ev.seq
    except Exception as e:
        if fail_closed:
            raise SandboxError(
                f"mandatory audit write failed ({event_type}): {e}"
            ) from e
        return None


def _run_sandbox_inner(
    *,
    db: Database,
    engagement_id: str,
    approval_id: str,
    adapter_name: str,
    adapter_version: str,
    request: SandboxRequest,
    engagements_root: Path,
    adapter_code_path: Path,
    actor: str,
) -> SandboxResult:
    # 1. Manifest
    mstore = ManifestStore(db)
    manifest = mstore.get_by_tool_version(adapter_name, adapter_version)
    if manifest is None:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "manifest_not_found",
                "adapter": adapter_name, "version": adapter_version})
        raise SandboxDenied(
            f"no manifest for {adapter_name!r} {adapter_version!r}"
        )
    if not manifest.manifest.network_access:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "manifest_not_network"})
        raise SandboxDenied(
            f"manifest {adapter_name!r} is not network-capable; "
            "SandboxRunner is for network adapters only"
        )
    ok, reason = mstore.verify(manifest.id)
    if not ok:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "manifest_drift", "detail": reason})
        raise SandboxDenied(f"manifest DB drift: {reason}")
    try:
        _verify_binary_digest(
            manifest.manifest.executable_path,
            manifest.manifest.executable_sha256,
        )
    except SandboxDenied as e:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "binary_digest", "detail": str(e)})
        raise

    # 2. Approval
    astore = ApprovalStore(db)
    approval = astore.get(approval_id)
    if approval is None:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "approval_not_found", "approval_id": approval_id})
        raise SandboxDenied(f"approval {approval_id!r} not found")
    if approval.engagement_id != engagement_id:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "approval_wrong_engagement"})
        raise SandboxDenied(
            f"approval {approval_id!r} belongs to another engagement"
        )

    # (v4.1) Proxy mode requires lab_environment=True for ALL requests,
    # not just protected-IP ones. The reviewer's finding: the protected-IP
    # branch checked lab, but a use_tls_proxy=True request against a public
    # IP proceeded without lab mode. The proxy runs in the main netns; its
    # upstream connect is not nft-filtered. Until kernel-level upstream
    # egress exists (deferred), every proxy execution is lab-only.
    if request.use_tls_proxy and not approval.lab_environment:
        _audit(db, engagement_id, actor, "sandbox_denied", {
            "reason": "proxy_mode_requires_lab",
            "approval_id": approval_id,
        })
        raise SandboxDenied(
            f"use_tls_proxy=True requires approval.lab_environment=True. "
            f"The proxy runs in the main namespace and its upstream connect "
            f"is not nft-filtered. See docs/egress-architecture-v1.1.md "
            f"§11.7. Re-issue the approval with --lab (requires "
            f"engagement.platform='lab')."
        )

    # M7.2c: path-restricted approvals allowed ONLY when use_tls_proxy=True.
    # The proxy terminates TLS and enforces prefixes at L7. Without the
    # proxy, nft cannot see paths and we fall back to the M7.1 refusal.
    profile = (approval.allowed_path_profile or "default").strip().lower()
    if profile not in ("", "default"):
        if not request.use_tls_proxy:
            _audit(db, engagement_id, actor, "sandbox_denied",
                   {"reason": "path_restricted_without_proxy",
                    "profile": approval.allowed_path_profile})
            raise SandboxDenied(
                f"path-restricted approval requires use_tls_proxy=True: "
                f"allowed_path_profile={approval.allowed_path_profile!r}. "
                "The nft egress layer cannot see HTTPS paths; only the "
                "L7 proxy can. Re-issue with use_tls_proxy=True, or "
                "change profile to 'default'."
            )
        prefixes = list(approval.allowed_path_prefixes or [])
        if not prefixes:
            _audit(db, engagement_id, actor, "sandbox_denied",
                   {"reason": "restricted_mode_no_prefixes"})
            raise SandboxDenied(
                "restricted path profile requires at least one prefix in "
                "allowed_path_prefixes (configuration error)"
            )

    # 2b. Provider authorization nesting
    try:
        _validate_provider_nesting(
            request.provider_endpoints,
            approval.approved_infrastructure_endpoints,
            manifest.manifest.infrastructure_endpoints,
        )
    except SandboxDenied as e:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "provider_nesting", "detail": str(e)})
        raise

    # 2c. Aggregate budget availability (P1.7)
    try:
        check_available(
            db, approval_id,
            estimated_requests=request.estimated_requests,
            # (v4.1) Real reservation: prior version passed 0, allowing
            # a single run to exceed remaining budget. Now passes the
            # adapter's declared estimate. If estimate > remaining, the
            # run refuses before spawn.
            estimated_bytes=0,
            estimated_runtime_seconds=float(request.timeout_seconds),
        )
    except BudgetExhausted as e:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "budget", "detail": e.reason})
        raise SandboxDenied(f"budget: {e.reason}") from e

    # 2c. Class 3 authorization gate (ECR v1.0.2)
    if manifest.manifest.execution_class >= 3:
        if not approval.intrusive_authorized:
            _audit(db, engagement_id, actor, "sandbox_denied", {
                "reason": "class3_no_intrusive_auth",
                "tool": adapter_name, "version": adapter_version,
            })
            raise SandboxDenied(
                f"tool {adapter_name!r} is Class 3 (intrusive). "
                "Approval must set intrusive_authorized=True. "
                "See docs/ecr-v1.0.2-class3-amendment.md."
            )
        if not approval.lab_environment:
            _audit(db, engagement_id, actor, "sandbox_denied", {
                "reason": "class3_lab_required",
                "tool": adapter_name, "version": adapter_version,
            })
            raise SandboxDenied(
                f"tool {adapter_name!r} is Class 3 (intrusive). "
                "Approval must set lab_environment=True (no real targets "
                "in v1.0.x). See docs/ecr-v1.0.2-class3-amendment.md."
            )

    # 3. argv[0] must match manifest executable
    if not request.argv:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "empty_argv"})
        raise SandboxDenied("empty argv")
    try:
        argv0_resolved = Path(request.argv[0]).resolve()
        manifest_bin = Path(manifest.manifest.executable_path).resolve()
    except (OSError, ValueError) as e:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "argv0_invalid", "detail": str(e)})
        raise SandboxDenied(f"argv[0] path invalid: {e}") from e
    if argv0_resolved != manifest_bin:
        # (batch-1) test-only escape: profiles named test/* that set
        # allow_argv0_override=True may launch a binary other than the
        # manifest's pinned one. Refused for any production profile.
        _prof_for_override = None
        if request.operation_profile is not None:
            try:
                from sentinel.runner.profiles import get_profile as _gp
                _prof_for_override = _gp(request.operation_profile)
            except Exception:
                _prof_for_override = None
        if _prof_for_override is None or not _prof_for_override.allow_argv0_override:
            _audit(db, engagement_id, actor, "sandbox_denied",
                   {"reason": "argv0_mismatch"})
            raise SandboxDenied(
                f"argv[0] {request.argv[0]!r} does not match manifest "
                f"executable {manifest.manifest.executable_path!r}"
            )
        # Override path — verify the actual binary is a real file.
        if not argv0_resolved.is_file():
            raise SandboxDenied(
                f"argv[0] override: {argv0_resolved} is not a file"
            )
        _audit(db, engagement_id, actor, "sandbox_argv0_override", {
            "manifest_bin": str(manifest_bin),
            "actual_bin": str(argv0_resolved),
            "profile": request.operation_profile,
        })

    # 3a. (P0.1) Network-capable operations MUST declare an operation
    # profile. Before this check, the runner accepted direct-argv network
    # operations with no profile verification at all — an adapter could
    # construct arbitrary argv and the only boundary was argv[0].
    if request.operation_profile is None:
        _audit(db, engagement_id, actor, "sandbox_denied", {
            "reason": "operation_profile_required",
            "adapter": adapter_name,
        })
        raise SandboxDenied(
            f"network-capable manifest {adapter_name!r} requires an "
            f"operation_profile. Adapters must declare a profile name "
            f"and profile_params; direct argv construction is not "
            f"permitted for network operations."
        )

    # 3b. (batch A) operation_profile must be listed in the manifest's
    # allowed_profiles. EXACT namespaced match only. Suffix matching was
    # a P0 bypass: scion/passive_discovery and theharvester/passive_discovery
    # share the suffix "passive_discovery", so a manifest declaring one
    # could authorize the other. Namespaced identity must be exact.
    _allowed = set(manifest.manifest.allowed_profiles)
    if request.operation_profile not in _allowed:
        _audit(db, engagement_id, actor, "sandbox_denied", {
            "reason": "operation_profile_not_in_manifest",
            "profile": request.operation_profile,
            "manifest_allowed": sorted(_allowed),
        })
        raise SandboxDenied(
            f"operation_profile {request.operation_profile!r} not in "
            f"manifest {adapter_name!r}.allowed_profiles "
            f"({sorted(_allowed) or '[]'}). Re-register the manifest "
            f"with this profile in allowed_profiles."
        )

    # 3c. (P0.1) Manifest-level prohibited tokens. Independent of the
    # profile's own prohibited_flags; both are enforced.
    for _tok in request.argv:
        for _forb in manifest.manifest.prohibited:
            if _tok == _forb or _tok.startswith(_forb + "="):
                _audit(db, engagement_id, actor, "sandbox_denied", {
                    "reason": "manifest_prohibited_token",
                    "forbidden": _forb,
                    "token": _tok[:200],
                })
                raise SandboxDenied(
                    f"argv contains manifest-prohibited token {_tok!r} "
                    f"(prohibited by manifest: {_forb!r})"
                )

    # 3b. Operation profile enforcement (M6-P0-A): rebuild canonical
    # argv from profile_params; refuse if it doesn't match what the
    # caller sent. This closes the gap where a different caller using
    # the same executable could send arbitrary flags.
    # 6B (batch-6): The approval binds a SPECIFIC operation profile.
    # A request for a different profile must use a fresh approval. This
    # check runs before the profile rebuild and is independent of the
    # earlier allowed_profiles check (which only verifies manifest
    # membership, not approval binding).
    if request.operation_profile and approval.operation_profile_id != request.operation_profile:
        # (batch A) Exact match only. Approval binds to the full
        # namespaced profile; suffix fallback would let an approval for
        # "scion/passive_discovery" run "theharvester/passive_discovery".
        if request.operation_profile != approval.operation_profile_id:
            _audit(db, engagement_id, actor, "sandbox_denied", {
                "reason": "operation_profile_not_bound_to_approval",
                "requested": request.operation_profile,
                "approval_bound": approval.operation_profile_id,
            })
            raise SandboxDenied(
                f"request operation_profile "
                f"{request.operation_profile!r} does not match the "
                f"approval's bound profile "
                f"{approval.operation_profile_id!r}. "
                f"Issue a fresh approval for this profile."
            )

    if request.operation_profile is not None:
        try:
            canonical_argv = build_argv_for_profile(
                profile_name=request.operation_profile,
                executable_path=manifest.manifest.executable_path,
                params=dict(request.profile_params or {}),
            )
        except ProfileError as e:
            _audit(db, engagement_id, actor, "sandbox_denied",
                   {"reason": "profile_build_failed",
                    "profile": request.operation_profile,
                    "detail": str(e)})
            raise SandboxDenied(f"profile {request.operation_profile!r}: {e}") from e
        _profile = get_profile(request.operation_profile)
        if _profile.requires_param_binding and not approval.normalized_arguments_hash:
            _audit(db, engagement_id, actor, "sandbox_denied", {
                "reason": "required_profile_params_not_bound",
                "profile": request.operation_profile,
            })
            raise SandboxDenied(
                f"profile {request.operation_profile!r} requires its parameters "
                "to be bound at approval issue time. Re-issue the approval."
            )
        if canonical_argv != request.argv:
            _audit(db, engagement_id, actor, "sandbox_denied",
                   {"reason": "argv_mismatch_vs_profile",
                    "profile": request.operation_profile,
                    "expected_hash": argv_hash(canonical_argv),
                    "actual_hash": argv_hash(request.argv)})
            raise SandboxDenied(
                f"request.argv does not match the canonical argv "
                f"produced by profile {request.operation_profile!r}. "
                "Adapters must pass profile_name + profile_params, not "
                "construct argv directly."
            )

    # (6A) If the approval bound specific profile params at issue time,
    # the request must use the SAME values. This is stricter than the
    # argv-vs-profile check: it forces the request's params (wordlist,
    # template set, etc.) to match what the operator pre-committed to.
    if request.operation_profile is not None:
        _bound_profile = get_profile(request.operation_profile)
    else:
        _bound_profile = None
    if _bound_profile and _bound_profile.requires_param_binding:
        required_keys = set(_bound_profile.param_binding_keys)
        missing_bound_keys = required_keys - set(approval.profile_params)
        if missing_bound_keys:
            _audit(db, engagement_id, actor, "sandbox_denied", {
                "reason": "required_profile_params_missing_from_approval",
                "profile": request.operation_profile,
                "missing_keys": sorted(missing_bound_keys),
            })
            raise SandboxDenied(
                f"approval is missing required bound parameters: "
                f"{sorted(missing_bound_keys)}"
            )

    if approval.normalized_arguments_hash:
        from sentinel.runner.profiles import params_hash as _params_hash
        # Extract ONLY the keys the approval bound. request.profile_params
        # may have additional run-time params (hostname, port) that were
        # not part of the original commitment — those are already covered
        # by other approval fields (canonical_hostnames, allowed_ports).
        _bound_keys = (
            set(_bound_profile.param_binding_keys)
            if _bound_profile and _bound_profile.requires_param_binding
            else set(approval.profile_params.keys())
        )
        _actual = {
            k: str(request.profile_params.get(k, ""))
            for k in _bound_keys
        }
        _actual_hash = _params_hash(_actual)
        if _actual_hash != approval.normalized_arguments_hash:
            _audit(db, engagement_id, actor, "sandbox_denied", {
                "reason": "normalized_arguments_hash_mismatch",
                "profile": request.operation_profile,
                "bound_keys": sorted(_bound_keys),
                "expected_prefix": approval.normalized_arguments_hash[:16],
                "actual_prefix": _actual_hash[:16],
            })
            raise SandboxDenied(
                f"request.profile_params do not match the params bound "
                f"at approval issue time (expected hash "
                f"{approval.normalized_arguments_hash[:16]}..., got "
                f"{_actual_hash[:16]}...). Re-issue the approval with "
                f"matching --profile-param values."
            )

    # 3c. Profile-level Class 3 gate. Fires when the operation_profile
    # declares execution_class >= 3, regardless of manifest class. This
    # lets a single binary (e.g. metasploit) host both a Class 2 detection
    # profile (metasploit/check) and a Class 3 profile (metasploit/exploit)
    # while gating the intrusive one on the same approval flags the
    # manifest-level gate requires.
    if request.operation_profile is not None:
        _profile = get_profile(request.operation_profile)
        if _profile.execution_class >= 3:
            if not approval.intrusive_authorized:
                _audit(db, engagement_id, actor, "sandbox_denied", {
                    "reason": "class3_profile_no_intrusive_auth",
                    "profile": request.operation_profile,
                    "profile_class": _profile.execution_class,
                })
                raise SandboxDenied(
                    f"profile {request.operation_profile!r} is Class 3 "
                    f"(intrusive). Approval must set intrusive_authorized=True. "
                    f"See docs/ecr-v1.0.2-class3-amendment.md."
                )
            if not approval.lab_environment:
                _audit(db, engagement_id, actor, "sandbox_denied", {
                    "reason": "class3_profile_lab_required",
                    "profile": request.operation_profile,
                    "profile_class": _profile.execution_class,
                })
                raise SandboxDenied(
                    f"profile {request.operation_profile!r} is Class 3 "
                    f"(intrusive). Approval must set lab_environment=True. "
                    f"See docs/ecr-v1.0.2-class3-amendment.md."
                )

    # 4. Hostname must be an approved asset for this engagement
    # 4. (batch A) The SCOPE TARGET must be an approved asset. Distinct
    # from `hostname` (the network destination). WHOIS/Dig keep hostname
    # pointing at their server/resolver so nft rules still apply, but set
    # scope_target to the domain being assessed. Everything else leaves
    # scope_target="" and falls back to hostname (backward compatible).
    _scope_check = request.scope_target or request.hostname
    target_asset_id = _asset_id_for_hostname(db, engagement_id, _scope_check)
    if target_asset_id is None:
        _audit(db, engagement_id, actor, "sandbox_denied",
               {"reason": "hostname_not_approved",
                "scope_target": _scope_check,
                "hostname": request.hostname})
        raise SandboxDenied(
            f"scope_target {_scope_check!r} is not in approved_assets "
            f"for engagement {engagement_id!r}"
        )

    # 5. Verify approval's tool identity matches the manifest we loaded
    if manifest.manifest.tool_name != approval.tool_name:
        raise SandboxDenied(
            f"approval tool_name {approval.tool_name!r} != manifest "
            f"{manifest.manifest.tool_name!r}"
        )
    if manifest.manifest.version != approval.tool_version:
        raise SandboxDenied(
            f"approval tool_version {approval.tool_version!r} != manifest "
            f"{manifest.manifest.version!r}"
        )
    _verify_provider_hash(approval)

    # 6. Build RequestContext from CURRENT state (not from approval)
    eng = EngagementStore(db).get(engagement_id)
    if eng is None:
        raise SandboxDenied(f"engagement {engagement_id!r} not found")

    current_target_ids = AssetStore(db).approved_ids(engagement_id)
    ctx = RequestContext(
        engagement_id=engagement_id,
        engagement_state=eng.state,
        policy_snapshot_hash=_current_policy_hash(
            db, engagement_id, approval.policy_snapshot_hash),
        scope_lock_hash=_current_scope_lock_hash(
            db, engagement_id, approval.scope_lock_hash),
        target_asset_ids_hash=target_asset_ids_hash(current_target_ids),
        target_asset_id=target_asset_id,
        tool_executable_sha256=manifest.manifest.executable_sha256,
        adapter_code_sha256=_current_adapter_code_sha256(adapter_code_path),
        manifest_hash=manifest.manifest_hash,
        egress_profile_id=_current_egress_profile_id(),
        port=request.port,
        protocol=request.protocol,
        http_method=request.method,
        path=request.path,
    )

    # 6. Gatekeeper — one check per port in the request
    all_ports = sorted({request.port, *request.additional_ports})
    for port in all_ports:
        # Rebuild ctx with this port; everything else is identical
        ctx_port = RequestContext(
            engagement_id=ctx.engagement_id,
            engagement_state=ctx.engagement_state,
            policy_snapshot_hash=ctx.policy_snapshot_hash,
            scope_lock_hash=ctx.scope_lock_hash,
            target_asset_ids_hash=ctx.target_asset_ids_hash,
            target_asset_id=ctx.target_asset_id,
            tool_executable_sha256=ctx.tool_executable_sha256,
            adapter_code_sha256=ctx.adapter_code_sha256,
            manifest_hash=ctx.manifest_hash,
            egress_profile_id=ctx.egress_profile_id,
            port=port,
            protocol=ctx.protocol,
            http_method=ctx.http_method,
            path=ctx.path,
        )
        decision = check_request(astore, approval_id, ctx_port)
        if not decision.allowed:
            _audit(db, engagement_id, actor, "sandbox_denied",
                   {"reason": "gatekeeper", "port": port,
                    "detail": decision.reason})
            raise SandboxDenied(
                f"gatekeeper denied (port {port}): {decision.reason}"
            )

    # 7. Resolve target + providers; protected-range check on every IP
    hostnames_to_resolve = [request.hostname, *request.provider_endpoints]
    resolved: dict[str, list[str]] = {}
    for h in hostnames_to_resolve:
        try:
            ips = _resolve_hostname(h)
        except Exception as e:
            _audit(db, engagement_id, actor, "sandbox_denied",
                   {"reason": "resolve_failed", "hostname": h,
                    "detail": str(e)})
            raise SandboxDenied(f"resolution failed for {h!r}: {e}") from e
        if not ips:
            _audit(db, engagement_id, actor, "sandbox_denied",
                   {"reason": "no_dns_answer", "hostname": h})
            raise SandboxDenied(f"{h!r} did not resolve")
        for ip in ips:
            protected, rng = _is_protected(ip)
            if protected:
                # (P3-A) The proxy runs in the MAIN netns. Its upstream
                # connect is NOT nft-filtered by the per-run ruleset.
                # Allowing it to reach 127.0.0.0/8, RFC1918, the WSL
                # gateway, or Docker networks would be a real bypass.
                #
                # Lab escape hatch: approval.lab_environment=True is
                # required to target a protected address in proxy mode.
                # Same flag the Class-3 gate uses; this is how the
                # egress test suite exercises the proxy against a
                # 127.0.0.1 fixture server.
                if request.use_tls_proxy and approval.lab_environment:
                    _audit(db, engagement_id, actor,
                           "sandbox_protected_target_proxied_lab",
                           {"hostname": h, "ip": ip, "range": rng})
                else:
                    _audit(db, engagement_id, actor, "sandbox_denied",
                           {"reason": (
                               "protected_ip_proxy_mode"
                               if request.use_tls_proxy
                               else "protected_ip"
                           ),
                            "hostname": h, "ip": ip, "range": rng})
                    msg = (
                        f"{h!r} resolved to protected IP {ip} "
                        f"(range {rng})"
                    )
                    if request.use_tls_proxy:
                        msg += (
                            " — proxy mode requires an approval with "
                            "lab_environment=True to target a protected "
                            "address. The proxy runs in the main netns "
                            "and is not nft-filtered; protected "
                            "upstreams are refused by default. See "
                            "docs/egress-architecture-v1.1.md §11.7."
                        )
                    raise SandboxDenied(msg)
        resolved[h] = ips

    primary_ip = resolved[request.hostname][0]

    # 8. Run inside the namespace
    # 8a. Approved destinations.
    #     - Target IPs approved only if requires_target_connection=True.
    #       Subfinder doesn't need the target, only crt.sh.
    #     - Provider IPs always approved on 443.
    # (batch A) 3-tuples (ip, port, protocol). run_namespace accepts
    # 2-tuples for backward compat, but the runner always emits 3-tuples
    # so UDP/53 (dig) and TCP providers are unambiguous.
    approved_destinations: list[tuple[str, int, str]] = []
    if request.requires_target_connection and not request.use_tls_proxy:
        approved_destinations.extend(
            (ip, port, request.target_protocol)
            for ip in resolved[request.hostname]
            for port in all_ports
        )
    # When use_tls_proxy=True, we do NOT approve target IPs directly;
    # the proxy port is added below once the proxy is listening.
    for provider in request.provider_endpoints:
        provider_port = request.provider_ports.get(provider, 443)
        provider_proto = request.provider_protocols.get(provider, "tcp")
        for ip in resolved[provider]:
            approved_destinations.append((ip, provider_port, provider_proto))

    # 8b. hostname_records = every hostname we're allowed to resolve
    hostname_records = {h: resolved[h] for h in hostnames_to_resolve}

    t0 = time.monotonic()
    namespace_name = ""
    revocation_reason: list[str | None] = [None]
    stop_watchdog = threading.Event()

    proxy = None
    proxy_ca = None
    proxy_port = None
    proxy_ca_path: Path | None = None
    proxy_ca_dir = None

    with run_namespace(
        approved=approved_destinations,
        hostname_records=hostname_records,
    ) as ns:
        namespace_name = ns.ns_name

        # Start proxy (M7.2b) if requested. The proxy binds to the veth's
        # main-side IP so the sandbox can reach it at 10.99.0.1:<port>.
        # Only that IP:port is added to INPUT chain as an approved dest.
        if request.use_tls_proxy:
            proxy_ca_dir = Path(f"/tmp/sentinel-proxy-ca-{ns.run_id}")
            proxy_ca = L7CA(proxy_ca_dir)
            proxy_ca.generate()
            proxy_ca_path = proxy_ca.ca_cert_path
            # The cert is public; make it readable by `nobody` in the sandbox
            try:
                import os as _os
                _os.chmod(proxy_ca_dir, 0o755)
                _os.chmod(proxy_ca_path, 0o644)
            except OSError:
                pass

            gatekeeper_filt = make_gatekeeper_filter(
                db, approval_id, cache_ttl=0.5,
            )
            # Pinned upstream IPs: use the EXACT IPs the gatekeeper
            # resolved, not a fresh lookup by the proxy. This closes the
            # DNS-rebinding vector (M7-P0-B). If the pin isn't here, the
            # proxy refuses CONNECT to that hostname.
            pinned = {
                h: resolved[h]
                for h in hostnames_to_resolve
                if h in resolved
            }
            proxy = TLSProxy(
                ca=proxy_ca,
                request_filter=gatekeeper_filt,
                listen_host=ns.main_gateway_ip,
                listen_port=0,
                upstream_ca_bundle=request.proxy_upstream_ca_bundle,
                allowed_connect_hosts=set(approval.canonical_hostnames),
                pinned_upstreams=pinned,
            )
            proxy.start()
            proxy_port = proxy.listen_port

            # INPUT chain allow: sandbox -> proxy
            # saddr-match because local delivery to 10.99.0.1 may rewrite
            # iifname to "lo". allow_protected=True is justified: the
            # proxy IP is on the veth subnet inside 10.0.0.0/8, and the
            # alternative (relocating the proxy to an un-denied range)
            # would require a second veth pair for no security benefit.
            # insert=True: the INPUT chain already contains
            # `ip saddr <ns>/32 ip daddr 10.0.0.0/8 drop` which matches
            # 10.99.0.1. Appending the accept rule would place it after
            # that drop -- never reached. Insert at head.
            _nft.add_approved(
                ns.main_gateway_ip, proxy_port,
                saddr=f"{ns.ns_ip}/32",
                chain=_nft.INPUT_CHAIN,
                comment=f"allow-proxy-{proxy_port}",
                allow_protected=True,
                insert=True,
            )
            _audit(db, engagement_id, actor, "sandbox_proxy_started", {
                "approval_id": approval_id,
                "proxy_port": proxy_port,
                "proxy_ip": ns.main_gateway_ip,
                "connect_hosts": sorted(approval.canonical_hostnames),
            }, fail_closed=True)

        # (batch-4) Snapshot the pre-run policy and manifest hashes for
        # the watchdog's drift check.
        _wd_initial_policy = _current_policy_hash(
            db, engagement_id, approval.policy_snapshot_hash)
        _wd_initial_manifest = manifest.manifest_hash

        def _watchdog():
            # SQLite connections are thread-bound by default. The watchdog
            # runs in its own thread, so it opens its own connection to the
            # same WAL-mode database file. This is safe: WAL allows multiple
            # readers/writers; our reads are simple SELECTs.
            wd_db = None
            try:
                wd_db = Database(db.path)
                while not stop_watchdog.is_set():
                    try:
                        current_approval = ApprovalStore(wd_db).get(approval_id)
                        current_eng = EngagementStore(wd_db).get(engagement_id)
                    except Exception as e:
                        # M6-02: fail closed. If we cannot verify current
                        # authorization state, we cannot assume the run is
                        # still permitted. Kill and revoke.
                        if not stop_watchdog.is_set():
                            revocation_reason[0] = f"watchdog_db_error:{type(e).__name__}"
                            try:
                                _kill_namespace_processes(ns.ns_name)
                            except Exception:
                                pass
                        return
                    reason = None
                    if current_approval is None:
                        reason = "approval_deleted"
                    elif current_approval.revoked_at_utc:
                        reason = "approval_revoked"
                    else:
                        try:
                            expires = datetime.fromisoformat(
                                current_approval.expires_at_utc
                            )
                            if expires <= datetime.now(timezone.utc):
                                reason = "approval_expired"
                        except (ValueError, TypeError):
                            pass
                    if reason is None and (
                        current_eng is None or current_eng.state != "active"
                    ):
                        reason = "engagement_not_active"

                    # (batch-4) Policy drift: a new policy_snapshots row
                    # with a different hash means the scope assumptions
                    # changed mid-run. Kill.
                    if reason is None:
                        try:
                            current_policy = _current_policy_hash(
                                wd_db, engagement_id, _wd_initial_policy)
                        except Exception:
                            current_policy = None
                        if (current_policy is not None
                                and current_policy != _wd_initial_policy):
                            reason = "policy_changed_mid_run"

                    # (batch-4) Manifest drift: the tool's declared hash
                    # changed (register-then-edit race, or registry
                    # tampering). Kill.
                    if reason is None:
                        try:
                            current_manifest_reg = ManifestStore(
                                wd_db).get_by_tool_version(
                                    adapter_name, adapter_version)
                        except Exception:
                            current_manifest_reg = None
                        if (current_manifest_reg is None
                                or current_manifest_reg.manifest_hash
                                != _wd_initial_manifest):
                            reason = "manifest_changed_mid_run"

                    if reason is not None:
                        if stop_watchdog.is_set():
                            return
                        revocation_reason[0] = reason
                        try:
                            _kill_namespace_processes(ns.ns_name)
                        except Exception:
                            pass
                        return
                    time.sleep(2)
            finally:
                if wd_db is not None:
                    try:
                        wd_db.close()
                    except Exception:
                        pass

        # Pre-spawn audits (unchanged).
        for provider in request.provider_endpoints:
            _audit(db, engagement_id, actor, "sandbox_provider_contact", {
                "approval_id": approval_id,
                "provider": provider,
                "provider_ips": resolved[provider],
                "target_hostname": request.hostname,
                "target_ip": primary_ip,
                "namespace": ns.ns_name,
                "manifest_id": manifest.id,
            }, fail_closed=True)

        _audit(db, engagement_id, actor, "sandbox_start", {
            "approval_id": approval_id,
            "adapter": adapter_name,
            "adapter_version": adapter_version,
            "target_hostname": request.hostname,
            "target_ip": primary_ip,
            "ports": list(all_ports),
            "providers": list(request.provider_endpoints),
            "namespace": ns.ns_name,
            "argv_sha256": hashlib.sha256(
                json.dumps(request.argv, separators=(",", ":")).encode()
            ).hexdigest(),
        }, fail_closed=True)

        scanner_path = Path(request.argv[0])
        try:
            st = scanner_path.stat()
        except OSError as e:
            _audit(db, engagement_id, actor, "sandbox_error",
                   {"reason": "scanner_stat_failed", "detail": str(e)},
                   fail_closed=False)
            raise SandboxError(
                f"cannot stat scanner {scanner_path}: {e}"
            ) from e
        if not (st.st_mode & 0o001):
            _audit(db, engagement_id, actor, "sandbox_error",
                   {"reason": "scanner_not_world_exec",
                    "path": str(scanner_path)},
                   fail_closed=False)
            raise SandboxError(
                f"scanner {scanner_path} is not world-executable; "
                "nobody cannot run it."
            )

        wrapped = [
                "ip", "netns", "exec", ns.ns_name,
                "setpriv",
                # M6-01: flags ordered so capability drops happen BEFORE
                # the uid drop. Dropping the bounding set requires
                # CAP_SETPCAP, which is lost after --reuid. Bounding set
                # first, then group/reuid.
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--reuid=nobody", "--regid=nogroup",
                "--clear-groups",
                "--no-new-privs",
                "--",
                *request.argv,
            ]
        # If proxying, inject HTTPS_PROXY and CA env vars. setpriv
        # preserves environment, so these reach the scanner unmodified.
        # (batch-4) Build the scanner env from the configured base. Default
        # is a minimal allowlist, not the parent's full env.
        import os as _os
        if request.env_mode == "inherit":
            scanner_env = dict(_os.environ)
        elif request.env_mode == "minimal":
            scanner_env = {
                k: v for k, v in _os.environ.items()
                if k in _MINIMAL_SCANNER_ENV_KEYS
            }
        else:
            raise SandboxError(
                f"unknown env_mode {request.env_mode!r}; "
                f"must be 'minimal' or 'inherit'"
            )

        # Proxy env injection (unchanged behaviour, applied to whichever
        # base env we built).
        if request.use_tls_proxy and proxy_port is not None and proxy_ca_path is not None:
            proxy_url = f"http://{ns.main_gateway_ip}:{proxy_port}"
            scanner_env["HTTPS_PROXY"] = proxy_url
            scanner_env["https_proxy"] = proxy_url
            scanner_env["HTTP_PROXY"] = proxy_url
            scanner_env["http_proxy"] = proxy_url
            scanner_env["SSL_CERT_FILE"] = str(proxy_ca_path)
            scanner_env["REQUESTS_CA_BUNDLE"] = str(proxy_ca_path)
            scanner_env["CURL_CA_BUNDLE"] = str(proxy_ca_path)
        # Merge caller-supplied env overrides (applied on top of the
        # base env built above — this runs regardless of env_mode).
        if request.env_overrides:
            scanner_env.update(request.env_overrides)

        try:
            reservation_id, aggregate_output_cap = reserve_budget(
                db, approval_id, requests=request.estimated_requests,
                requested_bytes=request.max_output_bytes * 2,
                runtime_seconds=float(request.timeout_seconds),
            )
        except BudgetExhausted as e:
            _audit(db, engagement_id, actor, "sandbox_denied",
                   {"reason": "budget_reservation", "detail": e.reason})
            raise SandboxDenied(f"execution budget exhausted: {e.reason}") from e
        per_stream_cap = max(1, aggregate_output_cap // 2)
        try:
            proc = subprocess.Popen(
                wrapped,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                env=scanner_env,
                cwd=str(request.cwd) if request.cwd is not None else None,
            )
        except BaseException as spawn_error:
            settle_budget(db, reservation_id, actual_bytes=0,
                          actual_runtime_seconds=0, spawned=False)
            _audit(db, engagement_id, actor, "sandbox_error", {
                "reason": "process_spawn_failed",
                "error_type": type(spawn_error).__name__,
            })
            raise
        watchdog_thread = None
        try:
            watchdog_thread = threading.Thread(target=_watchdog, daemon=True)
            watchdog_thread.start()
            (stdout_bytes, stderr_bytes,
             stdout_truncated, stderr_truncated) = _capped_communicate(
                proc, request.timeout_seconds, per_stream_cap,
            )
            stdout_data = stdout_bytes.decode("utf-8", errors="replace")
            stderr_data = stderr_bytes.decode("utf-8", errors="replace")
            timed_out = False
        except _CappedTimeout as timeout_error:
            try:
                _kill_namespace_processes(ns.ns_name)
            except Exception:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception:
                    pass
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            # Preserve bounded output already captured before timeout so
            # adapters can parse partial observations and ingest evidence.
            stdout_bytes = timeout_error.output or b""
            stderr_bytes = timeout_error.stderr or b""
            stdout_truncated = timeout_error.stdout_truncated
            stderr_truncated = timeout_error.stderr_truncated
            stdout_data = stdout_bytes.decode("utf-8", errors="replace")
            stderr_data = stderr_bytes.decode("utf-8", errors="replace")
            timed_out = True
        except BaseException as execution_error:
            try:
                _kill_namespace_processes(ns.ns_name)
            except Exception:
                pass
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
            settle_budget(
                db, reservation_id,
                actual_bytes=(len(locals().get("stdout_bytes", b""))
                              + len(locals().get("stderr_bytes", b""))),
                actual_runtime_seconds=time.monotonic() - t0,
                spawned=True,
            )
            _audit(db, engagement_id, actor, "sandbox_error", {
                "reason": "capture_or_watchdog_failure",
                "error_type": type(execution_error).__name__,
            })
            raise
        finally:
            stop_watchdog.set()
            if watchdog_thread is not None and watchdog_thread.ident is not None:
                try:
                    watchdog_thread.join(timeout=3)
                except Exception:
                    pass
        # Reconcile actual captured bytes/runtime against the reservation.
        # A concurrent authorization-store failure (detected by the
        # watchdog) may also make reservation settlement impossible, for
        # example if the approval row was removed. The process has already
        # been killed in that case; retain the fail-closed revocation result
        # and include the accounting failure in its audit details.
        budget_settlement_error = None
        try:
            settle_budget(
                db, reservation_id,
                actual_bytes=len(stdout_bytes) + len(stderr_bytes),
                actual_runtime_seconds=time.monotonic() - t0,
                spawned=True,
            )
        except Exception as settlement_error:
            if revocation_reason[0] is None:
                raise SandboxError(
                    "could not reconcile execution budget reservation"
                ) from settlement_error
            budget_settlement_error = type(settlement_error).__name__
            revocation_reason[0] += ":budget_settlement_failed"
        # Proxy stop, inside the with block so veth is still up.
        if proxy is not None:
            try:
                proxy.stop()
            except Exception:
                pass
            _audit(db, engagement_id, actor, "sandbox_proxy_stopped", {
                "approval_id": approval_id,
                "proxy_port": proxy_port,
            })

    if proxy_ca_dir is not None:
        import shutil as _sh
        _sh.rmtree(proxy_ca_dir, ignore_errors=True)

    duration = time.monotonic() - t0

    if revocation_reason[0] is not None:
        _audit(db, engagement_id, actor, "sandbox_revoked", {
            "reason": revocation_reason[0],
            "approval_id": approval_id,
            "namespace": namespace_name,
            "budget_settlement_error": budget_settlement_error,
        })
        raise SandboxRevoked(
            f"run revoked mid-execution: {revocation_reason[0]}"
        )

    audit_seq = _audit(db, engagement_id, actor,
                       "sandbox_timeout" if timed_out else "sandbox_ok", {
        "approval_id": approval_id,
        "manifest_id": manifest.id,
        "manifest_hash": manifest.manifest_hash,
        "namespace": namespace_name,
        "resolved_ip": primary_ip,
        "exit_code": proc.returncode,
        "duration_seconds": round(duration, 3),
        "argv": request.argv,
    })

    return SandboxResult(
        stdout=stdout_data,
        stderr=stderr_data,
        exit_code=proc.returncode,
        duration_seconds=duration,
        namespace_name=namespace_name,
        resolved_ip=primary_ip,
        audit_event_seq=audit_seq,
        used_providers=request.provider_endpoints,
        resolved_ips=tuple(resolved[request.hostname]),
        proxy_port=proxy_port,
        proxy_ca_path=proxy_ca_path,
        truncated_stdout=stdout_truncated,
        truncated_stderr=stderr_truncated,
        stdout_bytes=len(stdout_bytes),
        stderr_bytes=len(stderr_bytes),
        terminated=proc.returncode is not None and proc.returncode < 0,
        timed_out=timed_out,
        output_limit_bytes=aggregate_output_cap,
    )


def run_in_sandbox(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    adapter_name: str,
    adapter_version: str,
    request: SandboxRequest,
    engagements_root: Path,
    adapter_code_path: Path,
    actor: str = "operator",
) -> SandboxResult:
    """Launch a network-capable subprocess inside the sandbox.

    Refuses before any subprocess is spawned if the manifest, approval,
    or request fail validation. See _run_sandbox_inner for the full flow.
    """
    db_obj, owns_db = coerce_db(db)
    try:
        return _run_sandbox_inner(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=adapter_name,
            adapter_version=adapter_version,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=adapter_code_path,
            actor=actor,
        )
    finally:
        if owns_db:
            db_obj.close()
