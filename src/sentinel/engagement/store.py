# SPDX-License-Identifier: Apache-2.0
"""Engagement lifecycle store."""
from __future__ import annotations

import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sentinel.storage.db import Database, coerce_db
from sentinel.audit.store import AuditStore
from sentinel.paths import ensure_engagement_dirs
from .lifecycle import LifecycleError, is_allowed


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class Engagement:
    id: str
    platform: str
    program_name: str
    policy_url: str | None
    state: str
    created_at_utc: str
    updated_at_utc: str
    created_by: str
    closed_at_utc: str | None


def _row_to_engagement(row) -> Engagement:
    return Engagement(
        id=row["id"], platform=row["platform"], program_name=row["program_name"],
        policy_url=row["policy_url"], state=row["state"],
        created_at_utc=row["created_at_utc"], updated_at_utc=row["updated_at_utc"],
        created_by=row["created_by"], closed_at_utc=row["closed_at_utc"],
    )


class EngagementStore:
    def __init__(self, db: "Database | Path | str"):
        self._db, self._owns_db = coerce_db(db)

    def create(
        self, *,
        platform: str,
        program_name: str,
        policy_url: str | None,
        actor: str,
        engagements_root: Path,
    ) -> Engagement:
        eng_id = "eng_" + uuid.uuid4().hex[:16]
        dirs = ensure_engagement_dirs(engagements_root, eng_id)
        try:
            now = _iso_now()
            with self._db.transaction() as conn:
                conn.execute(
                    """INSERT INTO engagements
                       (id, platform, program_name, policy_url, state,
                        created_at_utc, updated_at_utc, created_by)
                       VALUES (?, ?, ?, ?, 'draft', ?, ?, ?)""",
                    (eng_id, platform, program_name, policy_url, now, now, actor),
                )
                AuditStore(self._db).append(
                    engagement_id=eng_id, actor=actor,
                    event_type="engagement_created", decision="ok",
                    details={"platform": platform, "program_name": program_name},
                )
        except Exception:
            shutil.rmtree(dirs["root"], ignore_errors=True)
            raise
        eng = self.get(eng_id)
        assert eng is not None
        return eng

    def get(self, engagement_id: str) -> Engagement | None:
        row = self._db.connection.execute(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
        return _row_to_engagement(row) if row else None

    def list_all(self) -> list[Engagement]:
        rows = self._db.connection.execute(
            "SELECT * FROM engagements ORDER BY created_at_utc"
        ).fetchall()
        return [_row_to_engagement(r) for r in rows]

    def transition(self, engagement_id: str, to_state: str, actor: str) -> Engagement:
        eng = self.get(engagement_id)
        if eng is None:
            raise LifecycleError(f"engagement {engagement_id!r} not found")
        if not is_allowed(eng.state, to_state):
            raise LifecycleError(f"cannot transition {eng.state} -> {to_state}")
        now = _iso_now()
        with self._db.transaction() as conn:
            if to_state == "closed":
                conn.execute(
                    "UPDATE engagements SET state = ?, updated_at_utc = ?, "
                    "closed_at_utc = ? WHERE id = ?",
                    (to_state, now, now, engagement_id),
                )
            else:
                conn.execute(
                    "UPDATE engagements SET state = ?, updated_at_utc = ? WHERE id = ?",
                    (to_state, now, engagement_id),
                )
            AuditStore(self._db).append(
                engagement_id=engagement_id, actor=actor,
                event_type="engagement_transition", decision=to_state,
                details={"from": eng.state, "to": to_state},
            )
        new_eng = self.get(engagement_id)
        assert new_eng is not None
        return new_eng

    def close(self) -> None:
        if getattr(self, "_owns_db", False):
            self._db.close()
