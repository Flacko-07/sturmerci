# SPDX-License-Identifier: Apache-2.0
"""Candidate and approved asset separation. Gate 2 (§5.1, G2-T03)."""
from __future__ import annotations

from sentinel.storage.db import Database, coerce_db

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sentinel.approval.store import target_asset_ids_hash


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


class AssetStore:
    def __init__(self, db: "Database | Path | str"):
        self._db, self._owns_db = coerce_db(db)

    def add_candidate(
        self, *, engagement_id: str, raw_value: str,
        canonical_value: str, asset_type: str, discovery_source: str,
        discovery_metadata: dict | None = None,
    ) -> str:
        """Insert a candidate asset.

        discovery_metadata (M7-04): adapter-specific structured detail
        (httpx: status/tech/TLS; nmap: port observations; subfinder:
        source). Stored as JSON; retrievable via get_candidate().
        """
        import json as _json
        cid = "ca_" + uuid.uuid4().hex
        self._db.connection.execute(
            "INSERT INTO candidate_assets "
            "(id, engagement_id, raw_value, canonical_value, asset_type, "
            "discovery_source, discovered_at_utc, review_state, "
            "discovery_metadata_json) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (cid, engagement_id, raw_value, canonical_value, asset_type,
             discovery_source, _iso(datetime.now(timezone.utc)), "pending",
             _json.dumps(discovery_metadata or {}, separators=(",", ":"))),
        )
        self._db.commit()
        return cid

    def get_candidate(self, candidate_id: str) -> dict | None:
        import json as _json
        cur = self._db.connection.execute(
            "SELECT * FROM candidate_assets WHERE id = ?", (candidate_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        d = dict(zip([d[0] for d in cur.description], row))
        # Decode metadata JSON for caller convenience
        raw = d.pop("discovery_metadata_json", "{}")
        try:
            d["discovery_metadata"] = _json.loads(raw)
        except Exception:
            d["discovery_metadata"] = {}
        return d

    # --- approval of a candidate ---

    def promote_candidate(self, candidate_id: str, approved_by: str) -> str:
        cand = self.get_candidate(candidate_id)
        if cand is None:
            raise ValueError(f"candidate {candidate_id!r} not found")
        if cand["review_state"] != "pending":
            raise ValueError(f"candidate {candidate_id!r} already {cand['review_state']}")
        aid = "aa_" + uuid.uuid4().hex
        self._db.connection.execute(
            "INSERT INTO approved_assets VALUES (?,?,?,?,?,?,?,?)",
            (aid, cand["engagement_id"], cand["raw_value"],
             cand["canonical_value"], cand["asset_type"], candidate_id,
             _iso(datetime.now(timezone.utc)), approved_by),
        )
        self._db.connection.execute(
            "UPDATE candidate_assets SET review_state = 'approved' WHERE id = ?",
            (candidate_id,),
        )
        self._db.commit()
        return aid

    # --- approved set ---

    def approved_ids(self, engagement_id: str) -> list[str]:
        cur = self._db.connection.execute(
            "SELECT id FROM approved_assets WHERE engagement_id = ? ORDER BY id",
            (engagement_id,),
        )
        return [r[0] for r in cur]

    def current_target_hash(self, engagement_id: str) -> str:
        return target_asset_ids_hash(self.approved_ids(engagement_id))

    def close(self) -> None:
        if getattr(self, "_owns_db", False):
            self._db.close()
