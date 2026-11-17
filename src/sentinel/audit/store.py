# SPDX-License-Identifier: Apache-2.0
"""Hash-chained append-only audit log. Gate 5 (§12.1).

Each event stores prev_hash and event_hash. The chain catches deletion or
modification of any row, provided the head is externally anchored (see
anchor.py). It is not inherently tamper-proof; see ECR §12.1.
"""

from __future__ import annotations

from sentinel.storage.db import Database, coerce_db

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditEvent:
    seq: int
    timestamp_utc: str
    engagement_id: str
    actor: str
    event_type: str
    decision: str
    details: dict[str, Any]
    prev_hash: str
    event_hash: str


def _canonical_json(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def _compute_hash(seq, ts, eng, actor, etype, decision, details, prev) -> str:
    payload = _canonical_json(
        {
            "seq": seq,
            "ts": ts,
            "engagement_id": eng,
            "actor": actor,
            "event_type": etype,
            "decision": decision,
            "details": details,
            "prev_hash": prev,
        }
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditStore:
    def __init__(self, db: "Database | Path | str"):
        self._db, self._owns_db = coerce_db(db)

    def _last(self) -> tuple[int, str]:
        cur = self._db.connection.execute(
            "SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        )
        row = cur.fetchone()
        if row is None:
            return -1, GENESIS
        return row[0], row[1]

    def append(
        self,
        *,
        engagement_id: str,
        actor: str,
        event_type: str,
        decision: str,
        details: dict | None = None,
    ) -> AuditEvent:
        details = details or {}
        # (v3 hardening) BEGIN IMMEDIATE serializes the read-then-write
        # between concurrent writers. Without it, two writers could both
        # read last_seq=N, both compute seq=N+1, and one loses on the
        # UNIQUE(seq) constraint. The atomic transaction also guarantees
        # the hash chain — prev_hash and event_hash — is computed against
        # the same last_seq that the INSERT commits.
        with self._db.transaction_immediate() as conn:
            last_seq, prev_hash = self._last()
            seq = last_seq + 1
            ts = datetime.now(timezone.utc).isoformat()
            ev_hash = _compute_hash(
                seq,
                ts,
                engagement_id,
                actor,
                event_type,
                decision,
                details,
                prev_hash,
            )
            conn.execute(
                """INSERT INTO audit_events
                   (seq, timestamp_utc, engagement_id, actor, event_type,
                    decision, details_json, prev_hash, event_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    seq,
                    ts,
                    engagement_id,
                    actor,
                    event_type,
                    decision,
                    _canonical_json(details),
                    prev_hash,
                    ev_hash,
                ),
            )
        return AuditEvent(
            seq,
            ts,
            engagement_id,
            actor,
            event_type,
            decision,
            details,
            prev_hash,
            ev_hash,
        )

    def verify_chain(self) -> tuple[bool, int | None, str]:
        cur = self._db.connection.execute(
            """SELECT seq, timestamp_utc, engagement_id, actor, event_type,
                      decision, details_json, prev_hash, event_hash
               FROM audit_events ORDER BY seq ASC"""
        )
        expected_prev = GENESIS
        expected_seq = 0
        for row in cur:
            seq, ts, eng, actor, etype, decision, dj, prev, eh = row
            if seq != expected_seq:
                return False, seq, f"sequence gap: expected {expected_seq}, got {seq}"
            if prev != expected_prev:
                return False, seq, f"prev_hash mismatch at seq {seq}"
            if (
                _compute_hash(
                    seq, ts, eng, actor, etype, decision, json.loads(dj), prev
                )
                != eh
            ):
                return False, seq, f"event_hash mismatch at seq {seq}"
            expected_prev = eh
            expected_seq += 1
        return True, None, "ok"

    def head(self) -> tuple[int, str]:
        return self._last()

    def get_event_hash(self, seq: int) -> str | None:
        cur = self._db.connection.execute(
            "SELECT event_hash FROM audit_events WHERE seq = ?", (seq,)
        )
        row = cur.fetchone()
        return row[0] if row else None

    def close(self) -> None:
        if getattr(self, "_owns_db", False):
            self._db.close()
