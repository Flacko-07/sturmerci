# SPDX-License-Identifier: Apache-2.0
"""Audited finding transitions.

Triage can create candidate rows, but this store is the only supported
application path for advancing their lifecycle. Every transition is
operator initiated and committed atomically with its audit event.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sentinel.audit.store import AuditStore
from sentinel.storage.db import Database, coerce_db


class FindingError(ValueError):
    """Invalid finding, evidence, or lifecycle transition."""


_ALLOWED = {
    "candidate": {"needs_evidence", "ready_for_review", "rejected"},
    "needs_evidence": {"ready_for_review", "rejected"},
    "ready_for_review": {"needs_evidence", "human_validated", "rejected"},
    "human_validated": {"report_ready", "duplicate", "rejected"},
    "report_ready": {"submitted", "human_validated", "duplicate", "rejected"},
    "submitted": {"resolved", "duplicate", "rejected"},
    "resolved": set(),
    "duplicate": set(),
    "rejected": set(),
}

_EVIDENCE_REQUIRED = {
    "ready_for_review",
    "human_validated",
    "report_ready",
    "submitted",
}
_SAFE_EVIDENCE_STATES = ("clean", "redacted")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FindingStore:
    def __init__(self, db: Database | Path | str):
        self._db, self._owns_db = coerce_db(db)

    def get(self, finding_id: str) -> dict | None:
        row = self._db.connection.execute(
            "SELECT * FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        return dict(row) if row else None

    def transition(
        self,
        finding_id: str,
        to_state: str,
        *,
        actor: str,
        note: str = "",
    ) -> dict:
        """Apply one explicit operator transition and append an audit event.

        The actor must be supplied by the operator-facing caller. This method
        is deliberately not exposed to model tools or triage output.
        """
        actor = actor.strip() if isinstance(actor, str) else ""
        if not actor:
            raise FindingError("actor is required for a human finding transition")
        if not isinstance(to_state, str):
            raise FindingError("target lifecycle state must be text")
        if not isinstance(note, str) or len(note) > 4000:
            raise FindingError("note must be text no longer than 4000 characters")

        with self._db.transaction() as conn:
            row = conn.execute(
                "SELECT id, engagement_id, asset_id, artifact_id, lifecycle_state "
                "FROM findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
            if row is None:
                raise FindingError(f"finding {finding_id!r} not found")

            from_state = row["lifecycle_state"]
            if to_state not in _ALLOWED.get(from_state, set()):
                raise FindingError(
                    f"cannot transition finding {finding_id!r} "
                    f"from {from_state!r} to {to_state!r}"
                )

            source_artifact = conn.execute(
                "SELECT engagement_id FROM artifacts WHERE id = ?",
                (row["artifact_id"],),
            ).fetchone()
            if (
                source_artifact is None
                or source_artifact["engagement_id"] != row["engagement_id"]
            ):
                raise FindingError(
                    "finding artifact is missing or belongs to another engagement"
                )

            if row["asset_id"] is not None:
                asset = conn.execute(
                    "SELECT 1 FROM approved_assets WHERE id = ? AND engagement_id = ?",
                    (row["asset_id"], row["engagement_id"]),
                ).fetchone()
                if asset is None:
                    raise FindingError(
                        "finding asset is missing or belongs to another engagement"
                    )

            if to_state in _EVIDENCE_REQUIRED:
                evidence = conn.execute(
                    "SELECT 1 FROM finding_evidence fe "
                    "JOIN artifacts a ON a.id = fe.artifact_id "
                    "WHERE fe.finding_id = ? AND a.engagement_id = ? "
                    "AND a.redaction_status IN (?, ?) LIMIT 1",
                    (finding_id, row["engagement_id"], *_SAFE_EVIDENCE_STATES),
                ).fetchone()
                if evidence is None:
                    raise FindingError(
                        f"transition to {to_state!r} requires safe, same-engagement evidence"
                    )

            now = _now()
            updated = conn.execute(
                "UPDATE findings SET lifecycle_state = ? "
                "WHERE id = ? AND lifecycle_state = ?",
                (to_state, finding_id, from_state),
            )
            if updated.rowcount != 1:
                raise FindingError(
                    "finding changed concurrently; reload before retrying"
                )

            AuditStore(self._db).append(
                engagement_id=row["engagement_id"],
                actor=actor,
                event_type="finding_transition",
                decision=to_state,
                details={
                    "finding_id": finding_id,
                    "from": from_state,
                    "to": to_state,
                    "note": note,
                    "transitioned_at_utc": now,
                },
            )

        result = self.get(finding_id)
        assert result is not None
        return result

    def close(self) -> None:
        if self._owns_db:
            self._db.close()
