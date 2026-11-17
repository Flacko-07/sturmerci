# SPDX-License-Identifier: Apache-2.0
"""Gatekeeper-backed filter for the L7 proxy (M7.2b).

The filter runs once per HTTP request inside the proxy. It consults the
approval record (cached briefly to avoid a DB query per request) and
decides whether the request proceeds.

Two checks, both must pass:
  1. Method is in approval.allowed_http_methods
  2. Path matches approval.allowed_path_profile:
       - "default"  -> any path allowed (inventory-only adapter, e.g.
                       httpx M7.1, which only ever sends GET /)
       - "/prefix"  -> path must start with /prefix (strict scope)
       - ""         -> treated as "default"

Why path is checked even when profile is "default": defense in depth.
A future adapter bug or a hostile tool could send a non-/ path. The
adapter knows to expect this; the tool shouldn't be trusted to obey.

Caching: approval is fetched from DB at most once per CACHE_TTL seconds.
A revocation takes effect within CACHE_TTL + 1 poll interval. Not
zero-latency, but bounded and documented. Set CACHE_TTL to 0 to disable
for tests that assert revocation timing.
"""
from __future__ import annotations

import threading
import urllib.parse
import time
from datetime import datetime, timezone
from pathlib import Path

from sentinel.approval.store import ApprovalStore
from sentinel.approval.state import (
    current_scope_lock_hash,
    current_policy_hash,
    current_manifest_hash,
)
from sentinel.engagement.store import EngagementStore
from sentinel.l7.proxy import ProxyDecision, ProxyRequest
from sentinel.storage.db import Database


# Approval freshness. The watchdog in SandboxRunner already polls every
# 2s; the filter only needs to catch a request that lands after a
# revocation. 1.0s TTL means worst-case 3s from revoke to first refusal.
# Approval cache TTL. Bounds the staleness window: if an approval is
# revoked or expires, requests continue to be served for up to
# CACHE_TTL_SECONDS afterwards. The default (1s) makes this a non-issue
# for the watchdog (which polls every 2s). Tests can set cache_ttl=0 to
# disable caching entirely, exercising per-request DB reads.
CACHE_TTL_SECONDS = 1.0


class _ApprovalCache:
    """Caches the approval for TTL seconds; per-thread DB connection.

    SQLite connections are thread-bound. The filter runs on the proxy's
    client-handler threads, so each thread must open its own Database.
    We use threading.local() to cache one ApprovalStore per thread, so a
    thread handling N connections does one Database() open, not N.
    """

    def __init__(self, db_path: Path, approval_id: str, ttl: float):
        self._db_path = db_path
        self._approval_id = approval_id
        self._ttl = ttl
        self._approval = None
        self._fetched_at = 0.0
        self._lock = threading.Lock()
        self._tls = threading.local()

    def _db(self) -> Database:
        """Per-thread Database for state reads. Same connection as _astore."""
        db = getattr(self._tls, "db", None)
        if db is None:
            # auto_migrate=False: the main thread already applied
            # migrations when it created the primary Database. A second
            # migration would race with -- or duplicate -- that work.
            db = Database(self._db_path, auto_migrate=False)
            self._tls.db = db
        return db

    def _astore(self) -> ApprovalStore:
        store = getattr(self._tls, "store", None)
        if store is None:
            store = ApprovalStore(self._db())
            self._tls.store = store
        return store

    def state(self, approval):
        """Fetch current state for the engagement/manifest bound by the
        approval. Returns a dict:
          engagement_state    : 'active' | 'paused' | 'closed' | None
          scope_lock_hash     : current hash of approved_assets
          policy_hash         : current policy_snapshots hash
          manifest_hash       : current registered manifest hash or None

        Called per-request by the filter. The queries are cheap
        (single-engagement SQLite in WAL mode) and correctness matters
        more than a micro-optimization here.
        """
        db = self._db()
        eng = EngagementStore(db).get(approval.engagement_id)
        return {
            "engagement_state": eng.state if eng else None,
            "scope_lock_hash": current_scope_lock_hash(
                db, approval.engagement_id),
            "policy_hash": current_policy_hash(
                db, approval.engagement_id,
                approval.policy_snapshot_hash),
            "manifest_hash": current_manifest_hash(
                db, approval.tool_name, approval.tool_version),
        }

    def get(self):
        now = time.monotonic()
        with self._lock:
            if (
                self._approval is not None
                and (now - self._fetched_at) < self._ttl
            ):
                return self._approval
            self._approval = self._astore().get(self._approval_id)
            self._fetched_at = now
            return self._approval


class PathCanonicalizationError(ValueError):
    """Path contains a security-relevant ambiguity. Deny."""


def _canonicalize_path(path: str) -> str:
    """Return a canonical path, or raise PathCanonicalizationError.

    Strict by design: rejects any encoding that could be interpreted
    differently by the upstream server than by our filter. Covers the
    M7-P0-D attacks:

      /api/../admin          -> parent segment
      /api/%2e%2e/admin      -> decoded to '/api/../admin'
      /api%2f..%2fadmin      -> encoded slash
      /api\\..\\admin         -> backslash
      /api/%252e%252e/admin  -> double-encoded
      /api\x00/../admin      -> control char

    Legitimate paths with percent-encoded benign chars (space, unicode)
    still work. Current-dir '.' segments are allowed; only '..' is
    rejected (it's the escape primitive).
    """
    if not path:
        return "/"
    for sep in ("?", "#"):
        if sep in path:
            path = path.split(sep, 1)[0]
    for ch in path:
        if ord(ch) < 0x20:
            raise PathCanonicalizationError(
                f"control character in path: {ord(ch):#x}"
            )
    if "\\" in path:
        raise PathCanonicalizationError("backslash in path")

    # Repeated unquoting: rejects if decoding introduces a new '/' (which
    # would change segment boundaries), backslash, or leaves '..' behind.
    current = path
    for _ in range(3):
        try:
            decoded = urllib.parse.unquote(current, errors="strict")
        except UnicodeDecodeError as e:
            raise PathCanonicalizationError(
                f"invalid percent-encoding: {e}"
            ) from e
        if decoded == current:
            break
        if decoded.count("/") != current.count("/"):
            raise PathCanonicalizationError("encoded slash in path")
        if "\\" in decoded:
            raise PathCanonicalizationError("encoded backslash in path")
        current = decoded

    if not current.startswith("/"):
        current = "/" + current
    for seg in current.split("/"):
        if seg == "..":
            raise PathCanonicalizationError(
                "parent-directory segment in path"
            )
    if "//" in current[1:]:
        raise PathCanonicalizationError("double-slash in path")
    return current


def _normalize_path(path: str) -> str:
    """Legacy shim kept for compatibility. Prefer _canonicalize_path."""
    return _canonicalize_path(path)


def _prefix_matches(path: str, prefix: str) -> bool:
    """Segment-safe prefix match: /api matches /api and /api/*, not /apix."""
    if not prefix:
        return True
    if not prefix.startswith("/"):
        prefix = "/" + prefix
    prefix = prefix.rstrip("/")
    if not prefix:
        return True  # prefix was "/" -> all paths
    if path == prefix:
        return True
    return path.startswith(prefix + "/")


def path_matches_prefixes(path: str, prefixes: list[str]) -> bool:
    """Return True iff path matches at least one prefix in the list.

    Denies on any canonicalization ambiguity (encoded slashes, dot
    segments, backslashes, control chars). This is the M7-P0-D fix.
    """
    try:
        p_norm = _canonicalize_path(path)
    except PathCanonicalizationError:
        return False
    if not prefixes:
        return False
    return any(_prefix_matches(p_norm, pref) for pref in prefixes)


def path_matches_profile(path: str, profile: str) -> bool:
    """Legacy single-string profile check (kept for the tests).

    Prefer path_matches_prefixes + allowed_path_prefixes in new code.
    """
    profile = (profile or "").strip()
    if profile == "" or profile.lower() == "default":
        return True
    return path_matches_prefixes(path, [profile])


def make_gatekeeper_filter(
    db: Database | Path | str,
    approval_id: str,
    *,
    cache_ttl: float = CACHE_TTL_SECONDS,
):
    """Return a RequestFilter that enforces method + path per approval.

    Accepts Database, Path, or str (the path). The Database object is
    not captured -- only its path is -- because the filter runs on
    proxy threads, each of which opens its own thread-local Database.
    """
    if isinstance(db, Database):
        db_path = db.path
    else:
        db_path = Path(db)
    cache = _ApprovalCache(db_path, approval_id, cache_ttl)

    def _filter(req: ProxyRequest) -> ProxyDecision:
        approval = cache.get()
        if approval is None:
            return ProxyDecision(False, "approval_not_found")
        if approval.revoked_at_utc:
            return ProxyDecision(False, "approval_revoked")

        # M7-06: re-check expiry on every request. The cache may hold a
        # pre-expiry approval for up to cache_ttl seconds; expiry must
        # not be deferred to the cache refresh.
        try:
            expires = datetime.fromisoformat(approval.expires_at_utc)
        except (ValueError, TypeError):
            return ProxyDecision(False, "approval_expiry_invalid")
        if expires <= datetime.now(timezone.utc):
            return ProxyDecision(False, "approval_expired")

        # (P3-C) Re-check the full approval state on every request. The
        # watchdog handles the sandbox-side kill, but the proxy runs in
        # a different thread+netns and could theoretically keep serving
        # if the watchdog missed. These checks close that gap.
        state = cache.state(approval)

        if state["engagement_state"] != "active":
            return ProxyDecision(
                False,
                f"engagement_not_active:{state['engagement_state']}",
            )

        # Scope drift: only enforce when the approval claims a scope
        # binding. Empty scope_lock_hash = unbound (tests, or an approval
        # created outside SandboxRunner). Production approvals always
        # carry a real hash — SandboxRunner sets it at issue time.
        if (approval.scope_lock_hash
                and state["scope_lock_hash"] != approval.scope_lock_hash):
            return ProxyDecision(False, "scope_lock_drift")

        # Policy drift: only enforce when the approval claims a policy
        # binding. Empty policy_snapshot_hash = unbound.
        if (approval.policy_snapshot_hash
                and state["policy_hash"] != approval.policy_snapshot_hash):
            return ProxyDecision(False, "policy_drift")

        # Manifest drift: only enforce when the approval claims a
        # manifest binding. Empty manifest_hash = unbound.
        if (approval.manifest_hash
                and state["manifest_hash"] != approval.manifest_hash):
            return ProxyDecision(
                False,
                f"manifest_drift:{state['manifest_hash'] or 'missing'}",
            )

        method = req.method.upper()
        allowed_methods = {m.upper() for m in approval.allowed_http_methods}
        if method not in allowed_methods:
            return ProxyDecision(
                False, f"method_not_allowed:{method}"
            )

        profile = (approval.allowed_path_profile or "default").strip().lower()
        if profile == "default" or profile == "":
            # Default profile: any path is allowed (inventory-only)
            return ProxyDecision(True, "ok")

        prefixes = list(getattr(approval, "allowed_path_prefixes", []) or [])
        if not prefixes:
            # Restricted mode without prefixes is a configuration error.
            # Deny (safer than accidentally allowing everything).
            return ProxyDecision(
                False, "restricted_mode_no_prefixes_configured"
            )
        if not path_matches_prefixes(req.path, prefixes):
            return ProxyDecision(
                False, f"path_out_of_prefixes:{','.join(prefixes)}"
            )

        return ProxyDecision(True, "ok")

    return _filter
