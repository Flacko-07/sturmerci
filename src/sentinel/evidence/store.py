# SPDX-License-Identifier: Apache-2.0
"""Artifact (evidence) metadata store."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinel.storage.db import Database, coerce_db


class EvidenceError(Exception):
    pass


class EvidenceNotFound(EvidenceError):
    pass


class EvidenceCrossEngagement(EvidenceError):
    pass


@dataclass(frozen=True, slots=True)
class Artifact:
    id: str
    engagement_id: str
    source_name: str
    content_type: str
    raw_sha256: str
    sanitized_sha256: str
    raw_size_bytes: int
    sanitized_size_bytes: int
    raw_path: str
    sanitized_path: str
    redaction_status: str
    unknown_format_triggered: bool
    actor: str
    created_at_utc: str
    truncated_output: bool = False
    execution_status: str = "COMPLETED"
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    output_limit_bytes: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    terminated: bool = False
    process_exit_code: int | None = None


class EvidenceStore:
    def __init__(self, db: "Database | Path | str"):
        self._db, self._owns_db = coerce_db(db)

    def get(self, evidence_id: str) -> Artifact | None:
        row = self._db.connection.execute(
            "SELECT * FROM artifacts WHERE id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            return None
        return Artifact(
            id=row["id"],
            engagement_id=row["engagement_id"],
            source_name=row["source_name"],
            content_type=row["content_type"],
            raw_sha256=row["raw_sha256"],
            sanitized_sha256=row["sanitized_sha256"],
            raw_size_bytes=row["raw_size_bytes"],
            sanitized_size_bytes=row["sanitized_size_bytes"],
            raw_path=row["raw_path"],
            sanitized_path=row["sanitized_path"],
            redaction_status=row["redaction_status"],
            unknown_format_triggered=bool(row["unknown_format_triggered"]),
            actor=row["actor"],
            created_at_utc=row["created_at_utc"],
            truncated_output=bool(row["truncated_output"]),
            execution_status=row["execution_status"],
            stdout_bytes=row["stdout_bytes"],
            stderr_bytes=row["stderr_bytes"],
            output_limit_bytes=row["output_limit_bytes"],
            stdout_truncated=bool(row["stdout_truncated"]),
            stderr_truncated=bool(row["stderr_truncated"]),
            timed_out=bool(row["timed_out"]),
            terminated=bool(row["terminated"]),
            process_exit_code=row["process_exit_code"],
        )

    def assert_in_engagement(self, evidence_id: str, engagement_id: str) -> Artifact:
        art = self.get(evidence_id)
        if art is None:
            raise EvidenceNotFound(f"evidence {evidence_id!r} does not exist")
        if art.engagement_id != engagement_id:
            raise EvidenceCrossEngagement(
                f"evidence {evidence_id!r} belongs to engagement {art.engagement_id!r}, "
                f"not {engagement_id!r}"
            )
        return art

    def close(self) -> None:
        if getattr(self, "_owns_db", False):
            self._db.close()


def release_held_artifact(
    db: "Database | Path | str",
    evidence_id: str,
    *,
    engagement_id: str,
    reviewer: str,
) -> None:
    """Flip a held_for_review artifact to redacted, after human verification.

    The reviewer must have inspected the sanitized_path and confirmed that
    no unredacted sensitive data survives. This action is audited.
    """
    from sentinel.audit.store import AuditStore
    from sentinel.storage.db import coerce_db as _coerce

    reviewer = reviewer.strip()
    if not reviewer:
        raise ValueError("reviewer is required to release held evidence")

    db_obj, owns = _coerce(db)
    try:
        store = EvidenceStore(db_obj)
        art = store.assert_in_engagement(evidence_id, engagement_id)
        if art.redaction_status != "held_for_review":
            raise ValueError(
                f"artifact {evidence_id!r} is {art.redaction_status!r}, "
                "not held_for_review"
            )
        # Transactional + conditional-on-held:
        #  - UPDATE only fires if the row is still held_for_review.
        #    Prevents a race where two operators release the same artifact
        #    and one overwrites the other's audit record.
        #  - AuditStore.append() called INSIDE the same transaction — its
        #    transaction_immediate() re-enters on the current connection
        #    via the _in_tx guard, so the UPDATE and the audit row commit
        #    or roll back together. Prior version committed UPDATE first,
        #    then audit — a crash between left status changed with no trail.
        with db_obj.transaction_immediate() as conn:
            result = conn.execute(
                "UPDATE artifacts SET redaction_status='redacted' "
                "WHERE id = ? AND redaction_status='held_for_review'",
                (evidence_id,),
            )
            if result.rowcount == 0:
                raise ValueError(
                    f"artifact {evidence_id!r} is no longer "
                    f"held_for_review — concurrent release or status change"
                )
            AuditStore(db_obj).append(
                engagement_id=engagement_id,
                actor=reviewer,
                event_type="evidence_released",
                decision="redacted",
                details={"evidence_id": evidence_id},
            )
    finally:
        if owns:
            db_obj.close()
