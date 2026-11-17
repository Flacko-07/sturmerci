# SPDX-License-Identifier: Apache-2.0
"""Ingest knowledge documents (frontmatter + body) into the FTS index."""
from __future__ import annotations

import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sentinel.storage.db import Database, coerce_db


_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)

REQUIRED_FIELDS = frozenset({
    "title", "topic", "source_url", "publisher", "version",
    "license", "review_status",
})


class IngestError(ValueError):
    """Malformed document, missing fields, or duplicate source_url conflict."""


def parse_document(text: str) -> tuple[dict, str]:
    """Split a knowledge file into (metadata dict, body str).

    Raises IngestError on malformed frontmatter or missing required fields.
    """
    m = _FRONTMATTER_RE.match(text)
    if not m:
        raise IngestError("document must start with '---' frontmatter block")
    front, body = m.group(1), m.group(2)
    meta: dict[str, str] = {}
    for line in front.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise IngestError(f"malformed frontmatter line: {line!r}")
        k, v = line.split(":", 1)
        meta[k.strip()] = v.strip()
    missing = REQUIRED_FIELDS - set(meta)
    if missing:
        raise IngestError(f"missing required frontmatter fields: {sorted(missing)}")
    if not body.strip():
        raise IngestError("document body is empty")
    return meta, body


def _entry_id_for_url(source_url: str) -> str:
    h = hashlib.sha256(source_url.encode("utf-8")).hexdigest()[:16]
    return f"kb_{h}"


def ingest_file(
    db: Database | Path | str, path: Path, *, ingested_by: str = "operator",
) -> str:
    """Ingest one knowledge file. Returns entry_id. Idempotent."""
    db_obj, owns = coerce_db(db)
    try:
        text = path.read_text(encoding="utf-8")
        meta, body = parse_document(text)
        # M8-1: hash covers metadata + body. If title/topic/version/
        # license/review_status/publisher changes but body does not, the
        # hash changes and the ingest path replaces the row. Without
        # this, a metadata-only edit is silently ignored.
        hash_input = "\n".join([
            meta.get("title", ""),
            meta.get("topic", ""),
            meta.get("source_url", ""),
            meta.get("version", ""),
            meta.get("license", ""),
            meta.get("publisher", ""),
            body,
        ])
        content_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        entry_id = _entry_id_for_url(meta["source_url"])

        if not ingested_by or not ingested_by.strip():
            raise IngestError("ingested_by must be a non-empty actor label")
        existing = db_obj.connection.execute(
            "SELECT current_revision_id FROM knowledge_entries WHERE id = ?",
            (entry_id,),
        ).fetchone()

        current = None
        if existing is not None and existing["current_revision_id"]:
            current = db_obj.connection.execute(
                "SELECT content_hash FROM knowledge_revisions WHERE revision_id=?",
                (existing["current_revision_id"],),
            ).fetchone()
        if current is not None and current["content_hash"] == content_hash:
            return entry_id  # unchanged

        revision_id = "kr_" + hashlib.sha256(
            f"{entry_id}:{content_hash}".encode("utf-8")
        ).hexdigest()[:24]
        ingested_at = datetime.now(timezone.utc).isoformat()

        with db_obj.transaction() as conn:
            if existing is None:
                conn.execute(
                    "INSERT INTO knowledge_entries "
                    "(id, title, topic, source_url, version, license, "
                    "content_hash, review_status, publisher, current_revision_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'unverified', ?, NULL)",
                    (entry_id, meta["title"], meta["topic"],
                     meta["source_url"], meta["version"], meta["license"],
                     content_hash, meta.get("publisher", "")),
                )
            conn.execute(
                "INSERT INTO knowledge_revisions "
                "(revision_id, entry_id, title, topic, source_url, publisher, "
                "version, license, body, content_hash, ingested_by, ingested_at_utc) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (revision_id, entry_id, meta["title"], meta["topic"],
                 meta["source_url"], meta.get("publisher", ""),
                 meta["version"], meta["license"], body, content_hash,
                 ingested_by.strip(), ingested_at),
            )
            conn.execute(
                "UPDATE knowledge_entries SET title=?, topic=?, source_url=?, "
                "version=?, license=?, content_hash=?, review_status='unverified', "
                "publisher=?, current_revision_id=? WHERE id=?",
                (meta["title"], meta["topic"], meta["source_url"],
                 meta["version"], meta["license"], content_hash,
                 meta.get("publisher", ""), revision_id, entry_id),
            )
            conn.execute(
                "INSERT INTO knowledge_fts (entry_id, title, body, topic) "
                "VALUES (?, ?, ?, ?)",
                (revision_id, meta["title"], body, meta["topic"]),
            )
        return entry_id
    finally:
        if owns:
            db_obj.close()


def ingest_directory(
    db: Database | Path | str, directory: Path, *, ingested_by: str = "operator",
) -> tuple[int, int]:
    """Ingest every .md file under `directory`, recursively.

    M8.5: rglob("*.md") so the domain layout knowledge/<topic>/*.md
    works. Without recursion, only top-level docs are ingested -- the
    14-domain structure would be invisible to the KB.

    Returns (files_processed, files_with_errors). Errors printed to
    stderr and skipped; one bad file doesn't abort the batch.
    """
    processed = 0
    errors = 0
    for path in sorted(Path(directory).rglob("*.md")):
        try:
            ingest_file(db, path, ingested_by=ingested_by)
            processed += 1
        except IngestError as e:
            errors += 1
            print(f"[kb-ingest] skipped {path.relative_to(directory)}: {e}",
                  file=sys.stderr)
    return processed, errors
