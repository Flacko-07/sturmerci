# SPDX-License-Identifier: Apache-2.0
"""Operational log channel — separate from audit_events.

Every message and details blob is redacted and then checked with the
final barrier before write. Secrets never reach the operational_logs table.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sentinel.storage.db import Database, coerce_db
from sentinel.evidence.redact import redact, assert_no_known_secrets


_ALLOWED_LEVELS = {"debug", "info", "warning", "error"}


class OpsLogger:
    def __init__(self, db: "Database | Path | str"):
        self._db, self._owns_db = coerce_db(db)

    def log(
        self,
        *,
        engagement_id: str,
        level: str,
        component: str,
        message: str,
        details: dict | None = None,
    ) -> str:
        if level not in _ALLOWED_LEVELS:
            raise ValueError(f"level {level!r} not in {_ALLOWED_LEVELS}")
        if not component or not message:
            raise ValueError("component and message are required")

        sanitized_msg, _ = redact(message)
        assert_no_known_secrets(sanitized_msg)

        details = details or {}
        sanitized_details_str, _ = redact(
            json.dumps(details, sort_keys=True, default=str)
        )
        assert_no_known_secrets(sanitized_details_str)

        log_id = "log_" + uuid.uuid4().hex[:16]
        with self._db.transaction() as conn:
            conn.execute(
                """INSERT INTO operational_logs
                   (id, engagement_id, timestamp_utc, level, component, message, details_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    log_id,
                    engagement_id,
                    datetime.now(timezone.utc).isoformat(),
                    level,
                    component,
                    sanitized_msg,
                    sanitized_details_str,
                ),
            )
        return log_id

    def close(self) -> None:
        if getattr(self, "_owns_db", False):
            self._db.close()
