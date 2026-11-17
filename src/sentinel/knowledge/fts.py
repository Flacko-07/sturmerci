# SPDX-License-Identifier: Apache-2.0
"""FTS5 search over the knowledge corpus. See docs/knowledge-base-design.md."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sentinel.storage.db import Database, coerce_db


# Common English stopwords. Removing them from queries means
# "how to test for SQL injection" searches for "SQL AND injection".
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "how",
        "to",
        "for",
        "of",
        "and",
        "or",
        "in",
        "on",
        "at",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "with",
        "by",
        "from",
        "about",
        "what",
        "which",
        "who",
        "why",
        "when",
        "where",
        "test",
        "testing",
        "check",
        "checking",
        "verify",
        "verifying",
        "find",
        "finding",
        "detect",
        "detecting",
        "do",
        "does",
        "can",
        "should",
        "i",
        "we",
        "you",
        "me",
        "my",
        "our",
        "your",
    }
)

_IDENTIFIER_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+)\b", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]+")


@dataclass(frozen=True, slots=True)
class KbHit:
    entry_id: str
    title: str
    topic: str
    source_url: str
    snippet: str
    rank: float


def _sanitize_query(query: str) -> str:
    """Turn a user query into an FTS5 MATCH expression.

    Returns "" for empty/all-stopword input (caller returns no hits).
    Otherwise AND-joins quoted tokens; CVE/CWE identifiers preserved
    as literals so they match exactly.
    """
    if not query or not query.strip():
        return ""
    ids = _IDENTIFIER_RE.findall(query)
    remaining = _IDENTIFIER_RE.sub(" ", query)
    tokens = _TOKEN_RE.findall(remaining.lower())
    kept = [t for t in tokens if t not in _STOPWORDS and len(t) > 1]
    # No fallback. If every token is a stopword or single-character,
    # there is nothing meaningful to search. Return "" -> caller gets [].
    parts: list[str] = []
    for i in ids:
        parts.append(f'"{i}"')
    for t in kept:
        parts.append(f'"{t}"')
    return " AND ".join(parts)


def search(
    db: Database | Path | str,
    query: str,
    *,
    limit: int = 5,
    filter_tags: list[str] | None = None,
) -> list[KbHit]:
    """Return up to `limit` knowledge-base hits ranked by BM25.

    Empty query returns []. Filter by topic via filter_tags.
    """
    if limit <= 0:
        return []
    sanitized = _sanitize_query(query)
    if not sanitized:
        return []

    db_obj, owns = coerce_db(db)
    try:
        # Only reviewed documents are searchable. Unreviewed/draft content
        # must not enter LLM prompt context (M8-P0-C). If an operator needs
        # to search drafts, that is a separate admin API.
        sql = (
            "SELECT f.entry_id, r.title, r.topic, r.source_url, "
            "snippet(knowledge_fts, 2, '<<', '>>', '...', 20) AS snip, "
            "bm25(knowledge_fts) AS rank "
            "FROM knowledge_fts f "
            "JOIN knowledge_revisions r ON r.revision_id = f.entry_id "
            "JOIN knowledge_entries e ON e.id = r.entry_id "
            "WHERE knowledge_fts MATCH ? "
            "AND e.current_revision_id = r.revision_id "
            "AND EXISTS (SELECT 1 FROM knowledge_reviews kr "
            "  WHERE kr.revision_id=r.revision_id "
            "    AND kr.content_hash=r.content_hash "
            "    AND kr.review_id=(SELECT kr2.review_id FROM knowledge_reviews kr2 "
            "      WHERE kr2.revision_id=r.revision_id "
            "      ORDER BY kr2.reviewed_at_utc DESC, kr2.review_id DESC LIMIT 1) "
            "    AND kr.decision='approved') "
        )
        params: list = [sanitized]
        if filter_tags:
            placeholders = ",".join("?" * len(filter_tags))
            sql += f"AND e.topic IN ({placeholders}) "
            params.extend(filter_tags)
        sql += "ORDER BY rank LIMIT ?"
        params.append(limit)

        rows = db_obj.connection.execute(sql, params).fetchall()
        if not rows:
            # AND produced no hits. Retry with OR over the same token set:
            # reviewer-recommended staged search. BM25 (ORDER BY rank) still
            # ranks by term frequency, so docs matching more tokens win.
            or_sanitized = _sanitize_query_or(query)
            if or_sanitized and or_sanitized != sanitized:
                params[0] = or_sanitized
                rows = db_obj.connection.execute(sql, params).fetchall()
        return [
            KbHit(
                entry_id=r["entry_id"],
                title=r["title"],
                topic=r["topic"],
                source_url=r["source_url"],
                snippet=r["snip"] or "",
                rank=r["rank"],
            )
            for r in rows
        ]
    finally:
        if owns:
            db_obj.close()


def _sanitize_query_or(query: str) -> str:
    """OR-joined MATCH expression over the same token set as _sanitize_query.

    Used as a fallback when the AND form returns no hits. BM25 ranking
    (ORDER BY rank in search()) penalizes documents matching fewer
    tokens, so the best-matching doc still wins. Reviewer-recommended
    staged search: exact identifiers -> phrase/AND -> OR fallback.
    """
    if not query or not query.strip():
        return ""
    ids = _IDENTIFIER_RE.findall(query)
    remaining = _IDENTIFIER_RE.sub(" ", query)
    tokens = _TOKEN_RE.findall(remaining.lower())
    kept = [t for t in tokens if t not in _STOPWORDS and len(t) > 1]
    seen: set[str] = set()
    parts: list[str] = []
    for t in [*ids, *kept]:
        if t in seen:
            continue
        seen.add(t)
        parts.append(f'"{t}"')
    return " OR ".join(parts)
