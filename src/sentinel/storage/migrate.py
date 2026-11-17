# SPDX-License-Identifier: Apache-2.0
"""Apply pending SQL migrations. Idempotent; version is the filename stem."""
from __future__ import annotations

from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .db import Database


def migrate(db: "Database", migrations_dir: Path | None = None) -> list[str]:
    if migrations_dir is None:
        migration_files = sorted(
            (
                entry
                for entry in resources.files("sentinel.storage")
                .joinpath("migrations").iterdir()
                if entry.name.endswith(".sql")
            ),
            key=lambda entry: entry.name,
        )
    else:
        migration_files = sorted(migrations_dir.glob("*.sql"))

    conn = db.connection
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version        TEXT PRIMARY KEY,
            applied_at_utc TEXT NOT NULL
        )
    """)

    applied = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
    newly_applied: list[str] = []

    for path in migration_files:
        version = path.stem
        if version in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        conn.executescript(sql)
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at_utc) VALUES (?, ?)",
            (version, datetime.now(timezone.utc).isoformat()),
        )
        newly_applied.append(version)

    return newly_applied
