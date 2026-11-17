# SPDX-License-Identifier: Apache-2.0
"""Markdown report renderer. See docs/report-design.md.

Safety: all untrusted content (finding summaries, evidence excerpts,
model output) is escaped for Markdown context. The reviewer must
never paste LLM output directly into a report without this layer.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from sentinel.storage.db import Database, coerce_db


class ReportError(Exception):
    """Cannot generate report (missing engagement, no findings, etc.)."""


# Characters that could break Markdown structure or inject links.
# We escape to prevent a hostile model output or evidence excerpt
# from rendering as HTML, javascript: URI, or table-breaking structure.
_MD_ESCAPE = {
    "\\": "\\\\",
    "`": "\\`",
    "*": "\\*",
    "_": "\\_",
    "{": "\\{",
    "}": "\\}",
    "[": "\\[",
    "]": "\\]",
    "(": "\\(",
    ")": "\\)",
    "#": "\\#",
    "+": "\\+",
    "-": "\\-",
    ".": "\\.",
    "!": "\\!",
    "|": "\\|",
    ">": "\\>",
    "<": "\\<",
}
_MD_ESCAPE_RE = re.compile("|".join(re.escape(c) for c in _MD_ESCAPE))
_DANGEROUS_URI_RE = re.compile(
    r"(?i)\b(?:javascript|data|vbscript|file)\s*:", re.IGNORECASE
)


def _escape_md(text: str) -> str:
    """Escape Markdown control chars + neutralize dangerous URIs."""
    if not text:
        return ""
    text = _DANGEROUS_URI_RE.sub("[BLOCKED-URI]:", text)
    return _MD_ESCAPE_RE.sub(lambda m: _MD_ESCAPE[m.group(0)], text)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_report(
    db: Database | str,
    *,
    engagement_id: str,
    include_candidate: bool = False,
) -> str:
    """Return a Markdown report string for the engagement."""
    db_obj, owns = coerce_db(db)
    try:
        eng = db_obj.connection.execute(
            "SELECT * FROM engagements WHERE id = ?",
            (engagement_id,),
        ).fetchone()
        if not eng:
            raise ReportError(f"engagement {engagement_id!r} not found")

        states = (
            (
                "candidate",
                "needs_evidence",
                "ready_for_review",
                "human_validated",
                "report_ready",
                "submitted",
                "resolved",
                "duplicate",
                "rejected",
            )
            if include_candidate
            else ("human_validated", "report_ready", "submitted", "resolved")
        )
        placeholders = ",".join("?" * len(states))
        findings = db_obj.connection.execute(
            f"SELECT * FROM findings WHERE engagement_id = ? "
            f"AND lifecycle_state IN ({placeholders}) "
            f"ORDER BY created_at_utc DESC",
            (engagement_id, *states),
        ).fetchall()

        # Verify every sanitized artifact referenced by the report before
        # emitting findings. This proves the bytes still match ingestion
        # metadata even though the Markdown output exposes hashes, not raw
        # evidence content.
        from sentinel.evidence.integrity import read_verified_sanitized

        evidence_ids = db_obj.connection.execute(
            "SELECT DISTINCT a.id, a.engagement_id, a.sanitized_path, "
            "a.sanitized_sha256, a.sanitized_size_bytes, a.execution_status "
            "FROM artifacts a JOIN findings f ON f.artifact_id=a.id "
            f"WHERE f.engagement_id=? AND f.lifecycle_state IN ({placeholders}) "
            "UNION SELECT DISTINCT a.id, a.engagement_id, a.sanitized_path, "
            "a.sanitized_sha256, a.sanitized_size_bytes, a.execution_status "
            "FROM finding_evidence fe JOIN artifacts a ON a.id=fe.artifact_id "
            "JOIN findings f ON f.id=fe.finding_id "
            f"WHERE f.engagement_id=? AND f.lifecycle_state IN ({placeholders})",
            (engagement_id, *states, engagement_id, *states),
        ).fetchall()
        for evidence in evidence_ids:
            if evidence["execution_status"] != "COMPLETED":
                from sentinel.audit.store import AuditStore

                AuditStore(db_obj).append(
                    engagement_id=engagement_id,
                    actor="report-generator",
                    event_type="report_rejected_incomplete_evidence",
                    decision="denied",
                    details={
                        "evidence_id": evidence["id"],
                        "execution_status": evidence["execution_status"],
                    },
                )
                raise ReportError(
                    f"evidence {evidence['id']!r} has execution status "
                    f"{evidence['execution_status']!r}; incomplete scanner "
                    "output cannot be represented as a completed assessment."
                )
            read_verified_sanitized(
                db_obj,
                artifact_id=evidence["id"],
                engagement_id=engagement_id,
                sanitized_path=evidence["sanitized_path"],
                expected_sha256=evidence["sanitized_sha256"],
                expected_size=evidence["sanitized_size_bytes"],
                actor="report-generator",
                consumer="report",
            )

        out: list[str] = []
        out.append(f"# Assessment Report — {_escape_md(eng['program_name'])}\n")
        out.append(f"**Platform:** {_escape_md(eng['platform'])}  ")
        out.append(f"**Engagement:** `{eng['id']}`  ")
        if eng["policy_url"]:
            out.append(f"**Policy:** {_escape_md(eng['policy_url'])}  ")
        out.append(f"**State:** {eng['state']}  ")
        out.append(f"**Report generated:** {_iso_now()}  ")
        out.append(
            f"**Findings included:** {len(findings)} "
            f"({'all states' if include_candidate else 'validated only'})\n"
        )

        if not findings:
            out.append("\n_No findings to report._\n")
            return "\n".join(out)

        # Summary table
        out.append("## Summary\n")
        out.append("| # | Severity | Category | Title | State |")
        out.append("|---|---|---|---|---|")
        for i, f in enumerate(findings, 1):
            out.append(
                f"| {i} | (operator-assigned) | "
                f"{_escape_md(f['candidate_category'])} | "
                f"{_escape_md((f['title'] or '')[:60])} | "
                f"{f['lifecycle_state']} |"
            )
        out.append("")

        # Per-finding detail
        out.append("## Findings\n")
        for i, f in enumerate(findings, 1):
            out.extend(_render_finding(db_obj, i, f))
        return "\n".join(out)
    finally:
        if owns:
            db_obj.close()


def _render_finding(db, idx: int, f) -> list[str]:
    out: list[str] = []
    out.append(f"### {idx}. {_escape_md(f['title'] or '(no title)')}\n")
    out.append(f"**ID:** `{f['id']}`  ")
    out.append(f"**State:** {f['lifecycle_state']}  ")
    out.append(f"**Category:** {_escape_md(f['candidate_category'])}  ")
    out.append(f"**Confidence:** {_escape_md(f['confidence_hint'])}  ")
    if f["created_at_utc"]:
        out.append(f"**Discovered:** {f['created_at_utc']}  ")
    out.append("")

    out.append(f"**Summary:** {_escape_md(f['summary'] or '')}\n")
    out.append(
        f"**Recommended next step:** {_escape_md(f['recommended_next_step'] or '')}\n"
    )

    refs = _json_or_empty(f["possible_references_json"])
    if refs:
        out.append(f"**References:** {', '.join(_escape_md(r) for r in refs)}\n")

    missing = _json_or_empty(f["missing_evidence_json"])
    if missing:
        out.append("**Missing evidence / open questions:**")
        for m in missing:
            out.append(f"- {_escape_md(m)}")
        out.append("")

    # Evidence artifacts (hashes + IDs; excerpts read from file on demand)
    ev_rows = db.connection.execute(
        "SELECT fe.evidence_id, a.raw_sha256, a.content_type, a.source_name "
        "FROM finding_evidence fe "
        "JOIN artifacts a ON a.id = fe.artifact_id "
        "WHERE fe.finding_id = ?",
        (f["id"],),
    ).fetchall()
    if ev_rows:
        out.append("**Evidence:**")
        for e in ev_rows:
            out.append(
                f"- `{e['evidence_id']}` — "
                f"{_escape_md(e['source_name'])} "
                f"({_escape_md(e['content_type'])}) "
                f"sha256 `{e['raw_sha256'][:16]}…`"
            )
        out.append("")

    out.append("---\n")
    return out


def _json_or_empty(raw: str | None) -> list:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        return v if isinstance(v, list) else []
    except (ValueError, TypeError):
        return []
