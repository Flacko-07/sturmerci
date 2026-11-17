# SPDX-License-Identifier: Apache-2.0
"""Explicit, append-only review workflow for knowledge revisions."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sentinel.audit.store import AuditStore
from sentinel.storage.db import Database, coerce_db


class KnowledgeReviewError(ValueError):
    """Invalid or stale knowledge review request."""


def review_revision(
    db: Database | Path | str,
    entry_id: str,
    *,
    reviewer: str,
    decision: str,
    rationale: str,
) -> str:
    """Record an independent review of the current immutable revision.

    Reviewer labels are audit attribution; this local single-user system
    does not authenticate them. Ingestion and review must use different
    labels to prevent source submitters from self-approving by accident.
    """
    if decision not in {"approved", "rejected"}:
        raise KnowledgeReviewError("decision must be approved or rejected")
    reviewer = reviewer.strip()
    rationale = rationale.strip()
    if not reviewer:
        raise KnowledgeReviewError("reviewer must be a non-empty actor label")
    if not rationale:
        raise KnowledgeReviewError("rationale must be provided")

    db_obj, owns = coerce_db(db)
    try:
        row = db_obj.connection.execute(
            "SELECT e.current_revision_id, r.content_hash, r.ingested_by "
            "FROM knowledge_entries e JOIN knowledge_revisions r "
            "ON r.revision_id=e.current_revision_id WHERE e.id=?",
            (entry_id,),
        ).fetchone()
        if row is None:
            raise KnowledgeReviewError(f"unknown knowledge entry {entry_id!r}")
        if row["ingested_by"].casefold() == reviewer.casefold():
            raise KnowledgeReviewError("reviewer must differ from ingested_by")

        review_id = "krev_" + uuid4().hex[:20]
        timestamp = datetime.now(timezone.utc).isoformat()
        with db_obj.transaction_immediate() as conn:
            # Recheck the head while holding the writer lock. A review of a
            # stale revision must never promote the newer document.
            current = conn.execute(
                "SELECT current_revision_id FROM knowledge_entries WHERE id=?",
                (entry_id,),
            ).fetchone()
            if current is None or current[0] != row["current_revision_id"]:
                raise KnowledgeReviewError("knowledge revision changed during review")
            conn.execute(
                "INSERT INTO knowledge_reviews "
                "(review_id, revision_id, entry_id, content_hash, decision, "
                "reviewer, reviewed_at_utc, rationale) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (review_id, row["current_revision_id"], entry_id,
                 row["content_hash"], decision, reviewer, timestamp, rationale),
            )
            conn.execute(
                "UPDATE knowledge_entries SET review_status=? WHERE id=?",
                ("reviewed" if decision == "approved" else "rejected", entry_id),
            )
            AuditStore(db_obj).append(
                engagement_id="system", actor=reviewer,
                event_type="knowledge_revision_reviewed", decision="ok",
                details={"entry_id": entry_id,
                         "revision_id": row["current_revision_id"],
                         "content_hash": row["content_hash"],
                         "review_decision": decision,
                         "review_id": review_id},
            )
        return review_id
    finally:
        if owns:
            db_obj.close()
