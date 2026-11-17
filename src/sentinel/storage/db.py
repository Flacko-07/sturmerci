# SPDX-License-Identifier: Apache-2.0
"""Consolidated SQLite database. One connection, one set of pragmas,
migration-driven schema, transaction support."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class Database:
    def __init__(self, path: Path | str, *, auto_migrate: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # (v3 hardening) The db holds approvals, scope, audit chain, and
        # evidence metadata. Default umask 022 creates db @ 0644 and dir
        # @ 0755 → every local user can read the audit chain and scope.
        # Restrict the parent dir to 0700 (blocks traversal + sidecar
        # access) and the db file to 0600. WAL/SHM files live in the
        # parent dir and are protected by the parent's mode.
        try:
            import os as _os
            _os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._conn = sqlite3.connect(str(self.path), isolation_level=None)
        try:
            import os as _os
            _os.chmod(self.path, 0o600)
        except OSError:
            pass
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._in_tx = False
        if auto_migrate:
            from .migrate import migrate
            migrate(self)

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def commit(self) -> None:
        # No-op while inside a Database.transaction(); caller commits.
        if not self._in_tx:
            # isolation_level=None + explicit BEGIN means we own commits.
            # A "commit" outside a tx is effectively flush of any autocommit state.
            self._conn.commit()

    @contextmanager
    def transaction_immediate(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE — acquires the write lock at BEGIN time.

        Use for read-modify-write where concurrent writers must serialize
        (e.g. audit seq allocation: SELECT MAX(seq) then INSERT). Plain
        ``transaction()`` uses BEGIN (DEFERRED), so two callers can both
        SELECT the same last_seq before either INSERT fires; the loser
        hits a UNIQUE(seq) IntegrityError.
        """
        if self._in_tx:
            yield self._conn
            return
        self._in_tx = True
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            self._in_tx = False

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if self._in_tx:
            yield self._conn
            return
        self._in_tx = True
        try:
            self._conn.execute("BEGIN")
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            self._in_tx = False

    def close(self) -> None:
        self._conn.close()


def coerce_db(x: Database | Path | str) -> tuple[Database, bool]:
    """Return (Database, owned_by_caller). Path -> new Database owned by caller."""
    if isinstance(x, Database):
        return x, False
    return Database(x), True
