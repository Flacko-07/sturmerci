# SPDX-License-Identifier: Apache-2.0
"""Retrieve similar validated findings for few-shot context (M8.4b).

Retrieval strategy: token-overlap scoring over the operator's own
validated findings for the same engagement. No embedding model, no
vector store -- the per-engagement corpus is small (dozens of validated
findings, not thousands), and FTS5-style keyword overlap is adequate.

Design rationale:
- Cross-engagement examples are REFUSED by SQL filter (engagement_id).
  Using another program's validated finding as a template would leak
  that program's specific evidence and violate isolation.
- Only finding.lifecycle_state in ('human_validated', 'report_ready',
  'resolved') are used. Candidates that were rejected or still in
  triage are noise; the operator has not endorsed them.
- Each example's evidence snippet comes from the SANITIZED artifact
  (artifacts.sanitized_path). The raw evidence never enters the prompt.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from sentinel.storage.db import Database, coerce_db


DEFAULT_K = 2
MAX_K = 3
MIN_SCORE = 0.10  # below this, example is not relevant enough
MAX_SNIPPET_CHARS = 500  # evidence excerpt per example

# Small stopword list. Different from fts.py because here we want a
# scoring signal, not a search query -- some words worth removing for
# BM25 are worth keeping for Jaccard.
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
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
        "to",
        "for",
        "with",
        "by",
        "from",
        "as",
        "that",
        "this",
        "these",
        "those",
        "it",
        "its",
        "if",
        "then",
        "than",
        "so",
        "such",
        "not",
        "no",
        "yes",
        "but",
        "however",
        "also",
        "which",
    }
)

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_\-]*")

# Lifecycle states that count as "validated" for few-shot.
_VALIDATED_STATES = ("human_validated", "report_ready", "resolved")


@dataclass(frozen=True, slots=True)
class FewShotExample:
    finding_id: str
    evidence_snippet: str
    output_json: str
    score: float


def _tokenize(text: str) -> set[str]:
    """Lowercase tokens, drop stopwords and short tokens."""
    if not text:
        return set()
    tokens = _TOKEN_RE.findall(text.lower())
    return {t for t in tokens if t not in _STOPWORDS and len(t) > 2}


def _score(evidence_tokens: set[str], finding_tokens: set[str]) -> float:
    """Jaccard-style overlap. Range [0, 1].

    Using overlap / |evidence| rather than strict Jaccard because a
    finding summary is usually shorter than the evidence; strict
    Jaccard would penalize findings with short summaries even when
    every evidence token matched.
    """
    if not evidence_tokens:
        return 0.0
    return len(evidence_tokens & finding_tokens) / len(evidence_tokens)


def _truncate(text: str, limit: int = MAX_SNIPPET_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _format_output_json(row) -> str:
    """Reconstruct a compact FindingTriageOutput from stored finding fields."""
    try:
        refs = json.loads(row["possible_references_json"] or "[]")
    except (ValueError, TypeError):
        refs = []
    try:
        missing = json.loads(row["missing_evidence_json"] or "[]")
    except (ValueError, TypeError):
        missing = []
    payload = {
        "task_type": "finding_triage",
        "summary": row["summary"],
        "candidate_category": row["candidate_category"],
        "possible_references": refs,
        "evidence_ids": ["(omitted in example)"],
        "missing_evidence": missing,
        "confidence_hint": row["confidence_hint"],
        "recommended_next_step": row["recommended_next_step"],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def retrieve_similar_examples(
    db: Database | Path | str,
    *,
    engagement_id: str,
    evidence_text: str,
    k: int = DEFAULT_K,
) -> list[FewShotExample]:
    """Return up to k operator-validated findings from this engagement,
    ranked by token overlap with `evidence_text`.

    Examples below MIN_SCORE are excluded so an unrelated finding is not
    presented as a template. Empty result means "use V1 prompt".
    """
    if k <= 0:
        return []
    k = min(k, MAX_K)

    evidence_tokens = _tokenize(evidence_text)
    if not evidence_tokens:
        return []

    db_obj, owns = coerce_db(db)
    try:
        placeholders = ",".join("?" * len(_VALIDATED_STATES))
        rows = db_obj.connection.execute(
            f"SELECT f.id, f.summary, f.candidate_category, "
            f"       f.confidence_hint, f.recommended_next_step, "
            f"       f.missing_evidence_json, f.possible_references_json, "
            f"       a.sanitized_path "
            f"FROM findings f "
            f"JOIN artifacts a ON a.id = f.artifact_id "
            f"WHERE f.engagement_id = ? "
            f"  AND f.lifecycle_state IN ({placeholders})",
            (engagement_id, *_VALIDATED_STATES),
        ).fetchall()

        scored: list[FewShotExample] = []
        for row in rows:
            finding_tokens = _tokenize(
                f"{row['summary'] or ''} "
                f"{row['recommended_next_step'] or ''} "
                f"{row['possible_references_json'] or ''}"
            )
            score = _score(evidence_tokens, finding_tokens)
            if score < MIN_SCORE:
                continue
            try:
                snippet = Path(row["sanitized_path"]).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                continue
            scored.append(
                FewShotExample(
                    finding_id=row["id"],
                    evidence_snippet=_truncate(snippet),
                    output_json=_format_output_json(row),
                    score=score,
                )
            )

        scored.sort(key=lambda e: e.score, reverse=True)
        return scored[:k]
    finally:
        if owns:
            db_obj.close()
