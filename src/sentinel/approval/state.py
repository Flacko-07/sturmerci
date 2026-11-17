# SPDX-License-Identifier: Apache-2.0
"""Computed state hashes used for approval revalidation.

Extracted from sandbox_runner so that the L7 gatekeeper filter can
re-check the same state on every request without importing the runner
(which would be circular — sandbox_runner imports from l7).

All three functions are read-only and safe to call from any thread that
owns a Database connection.
"""

from __future__ import annotations

import hashlib
import json

from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore


def current_scope_lock_hash(
    db: Database, engagement_id: str, fallback: str = ""
) -> str:
    """SHA-256 of the current approved_assets set for an engagement.

    Same value sandbox_runner computes at run start. If an asset is
    added or removed, this hash changes and approvals bound to the old
    hash are invalid.
    """
    rows = db.connection.execute(
        "SELECT id, canonical_value, asset_type FROM approved_assets "
        "WHERE engagement_id = ? ORDER BY id",
        (engagement_id,),
    ).fetchall()
    payload = [[r["id"], r["canonical_value"], r["asset_type"]] for r in rows]
    return hashlib.sha256(
        json.dumps(payload, separators=(",", ":")).encode()
    ).hexdigest()


def current_policy_hash(db: Database, engagement_id: str, fallback: str = "") -> str:
    """Latest policy_snapshots.policy_hash for the engagement, or fallback."""
    row = db.connection.execute(
        "SELECT policy_hash FROM policy_snapshots "
        "WHERE engagement_id = ? "
        "ORDER BY created_at_utc DESC LIMIT 1",
        (engagement_id,),
    ).fetchone()
    return row["policy_hash"] if row else fallback


def current_manifest_hash(db: Database, tool_name: str, version: str) -> str | None:
    """Registered manifest_hash for (tool, version), or None if absent."""
    reg = ManifestStore(db).get_by_tool_version(tool_name, version)
    return reg.manifest_hash if reg else None
