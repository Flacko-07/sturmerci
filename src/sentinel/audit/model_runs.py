# SPDX-License-Identifier: Apache-2.0
"""Model call ledger. Gate 3 (§6.4, G3-T08)."""
from __future__ import annotations

from sentinel.storage.db import Database, coerce_db

import json
import sqlite3
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ALLOWED_OUTCOMES = {"ok", "schema_invalid", "timeout", "error"}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class ModelRunRecord:
    run_id: str
    engagement_id: str
    model_id: str
    model_digest: str | None
    prompt_template_hash: str
    sanitized_input_hash: str
    schema_version: str
    settings: dict[str, Any]
    input_tokens: int | None
    output_tokens: int | None
    duration_sec: float
    outcome: str
    retry_count: int
    dropped_references: int
    created_at_utc: str


class ModelRunStore:
    def __init__(self, db: "Database | Path | str"):
        self._db, self._owns_db = coerce_db(db)

    def record(
        self, *,
        engagement_id: str,
        model_id: str,
        prompt_template_hash: str,
        sanitized_input_hash: str,
        schema_version: str,
        settings: dict[str, Any],
        duration_sec: float,
        outcome: str,
        model_digest: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        retry_count: int = 0,
        dropped_references: int = 0,
    ) -> ModelRunRecord:
        if outcome not in _ALLOWED_OUTCOMES:
            raise ValueError(f"outcome {outcome!r} not in {_ALLOWED_OUTCOMES}")
        for name, val in (
            ("prompt_template_hash", prompt_template_hash),
            ("sanitized_input_hash", sanitized_input_hash),
        ):
            if not isinstance(val, str) or not val:
                raise ValueError(f"{name} required and non-empty")
        rec = ModelRunRecord(
            run_id="mr_" + uuid.uuid4().hex,
            engagement_id=engagement_id,
            model_id=model_id,
            model_digest=model_digest,
            prompt_template_hash=prompt_template_hash,
            sanitized_input_hash=sanitized_input_hash,
            schema_version=schema_version,
            settings=settings,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duration_sec=duration_sec,
            outcome=outcome,
            retry_count=retry_count,
            dropped_references=dropped_references,
            created_at_utc=_iso(datetime.now(timezone.utc)),
        )
        d = asdict(rec)
        d["settings_json"] = json.dumps(rec.settings, sort_keys=True)
        d.pop("settings")
        cols = list(d.keys())
        self._db.connection.execute(
            f"INSERT INTO model_runs ({','.join(cols)}) VALUES "
            f"({','.join('?' * len(cols))})",
            tuple(d[c] for c in cols),
        )
        self._db.commit()
        return rec

    def all(self) -> list[dict]:
        cur = self._db.connection.execute("SELECT * FROM model_runs ORDER BY created_at_utc")
        return [dict(zip([d[0] for d in cur.description], row)) for row in cur]

    def set_dropped_references(self, run_id: str, count: int) -> None:
        """M8-3: post-call update after reference validation.

        call_structured() writes dropped_references=0 because the LLM
        client does not know what references the KB recognizes -- that
        happens in the triage pipeline, after the call returns. This
        helper lets the pipeline record the true count on the same row.
        """
        if count < 0:
            raise ValueError(f"count must be >= 0, got {count}")
        self._db.connection.execute(
            "UPDATE model_runs SET dropped_references = ? WHERE run_id = ?",
            (count, run_id),
        )
        self._db.commit()

    def close(self) -> None:
        if getattr(self, "_owns_db", False):
            self._db.close()
