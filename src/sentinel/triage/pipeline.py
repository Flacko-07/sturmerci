# SPDX-License-Identifier: Apache-2.0
"""Evidence -> KB -> LLM -> persisted candidate finding. See docs/triage-pipeline-design.md."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sentinel.audit.store import AuditStore
from sentinel.evidence.store import EvidenceStore
from sentinel.knowledge.fts import KbHit, search
from sentinel.knowledge.refs import resolve_and_filter
from sentinel.llm.client import call_structured
from sentinel.llm.prompts import TRIAGE_V1, TRIAGE_V2
from sentinel.models.contracts import FindingTriageOutput
from sentinel.storage.db import Database, coerce_db
from sentinel.triage.query_builder import build_kb_query


class TriageError(Exception):
    """Pipeline refused or failed before a finding was written."""


@dataclass(frozen=True, slots=True)
class TriageResult:
    finding_id: str
    artifact_id: str
    output: FindingTriageOutput
    kb_hits: list[KbHit]
    dropped_references: int
    dropped_evidence: int
    model_run_id: str
    examples_used: tuple[str, ...] = ()


def triage_artifact(
    *,
    db: Database | Path | str,
    engagement_id: str,
    artifact_id: str,
    actor: str = "operator",
    model: str = "qwen3:1.7b",
    max_kb_hits: int = 3,
    max_evidence_chars: int = 8000,
    use_fewshot: bool = False,
    fewshot_k: int = 2,
) -> TriageResult:
    """Run the triage pipeline for one artifact. See design doc."""
    db_obj, owns = coerce_db(db)
    try:
        art = EvidenceStore(db_obj).get(artifact_id)
        if art is None:
            raise TriageError(f"artifact {artifact_id!r} not found")
        if art.engagement_id != engagement_id:
            raise TriageError(
                f"artifact {artifact_id!r} belongs to "
                f"{art.engagement_id!r}, not {engagement_id!r}"
            )

        # M8-P0-A: evidence held for human review must NOT reach the LLM.
        # The ingest pipeline flags unknown-format material (unknown long
        # token triggered) as held_for_review precisely because it could
        # contain a secret that redact() didn't recognize. Sending it to
        # the model would bypass Gate 4.
        if art.redaction_status == "held_for_review":
            raise TriageError(
                f"artifact {artifact_id!r} is held for review; an operator "
                "must release it before triage can proceed. See "
                "EvidenceStore.release_held_artifact()."
            )
        if art.truncated_output or art.execution_status != "COMPLETED":
            raise TriageError(
                f"artifact {artifact_id!r} is incomplete: "
                f"execution status '{art.execution_status}' "
                f"(truncated_output={art.truncated_output}); refusing to "
                "send partial or failed scanner output to the model."
            )

        from sentinel.evidence.integrity import (
            EvidenceIntegrityError, read_verified_sanitized,
        )
        try:
            sanitized_bytes = read_verified_sanitized(
                db_obj, artifact_id=artifact_id, engagement_id=engagement_id,
                sanitized_path=art.sanitized_path,
                expected_sha256=art.sanitized_sha256,
                expected_size=art.sanitized_size_bytes,
                actor=actor, consumer="triage",
            )
            sanitized = sanitized_bytes.decode("utf-8")
        except (EvidenceIntegrityError, UnicodeDecodeError) as e:
            raise TriageError(f"sanitized evidence rejected: {e}") from e

        truncated = sanitized[:max_evidence_chars]

        query = build_kb_query(
            source_name=art.source_name,
            content_type=art.content_type,
            content=truncated,
        )
        kb_hits = search(db_obj, query, limit=max_kb_hits) if query else []

        user_content = _assemble_user_content(art, truncated, kb_hits)

        # M8.4b: optional few-shot from operator-validated findings.
        # Disabled by default; enabled per call. Old callers (V1) are
        # unaffected. Prompt hash distinguishes V1 runs from V2 runs.
        examples_used: list[str] = []
        prompt_ctx: dict[str, str] = {}
        if use_fewshot:
            from sentinel.llm.fewshot import retrieve_similar_examples
            examples = retrieve_similar_examples(
                db_obj,
                engagement_id=engagement_id,
                evidence_text=truncated,
                k=fewshot_k,
            )
            examples_used = [ex.finding_id for ex in examples]
            prompt = TRIAGE_V2
            prompt_ctx = {"examples": _format_examples(examples)}
        else:
            prompt = TRIAGE_V1

        try:
            output, run_rec = call_structured(
                db=db_obj,
                engagement_id=engagement_id,
                prompt=prompt,
                user_content=user_content,
                schema=FindingTriageOutput,
                schema_version="FindingTriageOutput/v1",
                prompt_context=prompt_ctx or None,
                model=model,
            )
        except Exception as e:
            raise TriageError(f"LLM call failed: {e}") from e

        valid_ev: list[str] = []
        dropped_ev = 0
        # (bug 10 fix) dedupe model-emitted evidence ids before insert

        _deduped_evidence_ids = list(dict.fromkeys(output.evidence_ids))

        for ev_id in _deduped_evidence_ids:
        # (bug 10 fix) dedupe — model can repeat evidence_ids
            if ev_id == artifact_id:
                valid_ev.append(ev_id)
                continue
            other = EvidenceStore(db_obj).get(ev_id)
            if other is not None and other.engagement_id == engagement_id:
                valid_ev.append(ev_id)
            else:
                dropped_ev += 1
        if not valid_ev:
            raise TriageError(
                f"no valid evidence IDs in model output "
                f"({dropped_ev} fabricated)"
            )

        # (v3-follow-up, NVD integration) Pass db so the reference
        # validator can drop hallucinated CVEs when the local cve_entries
        # cache is populated. Cache empty or db=None → permissive,
        # backwards-compatible with pre-NVD tests.
        # (v4.3) Capture per-CVE status so the operator can query
        # "which findings reference unverified CVEs". Prior version
        # discarded the status map, so every finding's CVE references
        # were indistinguishable from validated ones.
        cve_statuses: dict[str, str] = {}
        reference_details: dict[str, dict] = {}
        kept_refs, dropped_refs = resolve_and_filter(
            list(output.possible_references),
            db=db,
            cve_statuses=cve_statuses,
            reference_details=reference_details,
        )

        # M8-3: update model_run with the true dropped_references count
        # now that KB validation has run. The LLM client wrote 0 because
        # it does not know what the KB recognizes.
        try:
            from sentinel.audit.model_runs import ModelRunStore as _MRS
            _MRS(db_obj).set_dropped_references(run_rec.run_id, dropped_refs)
        except Exception:
            pass  # not fatal; audit trail shows finding anyway

        # M8-4: findings + evidence + audit written in ONE transaction.
        # If audit fails, the finding rolls back -- triage either fully
        # succeeds or leaves no trace.
        finding_id = _write_finding_with_audit(
            db_obj,
            engagement_id=engagement_id,
            artifact_id=art.id,
            output=output,
            valid_evidence_ids=valid_ev,
            kept_references=kept_refs,
            kb_hits=kb_hits,
            model_run_id=run_rec.run_id,
            actor=actor,
            dropped_refs=dropped_refs,
            dropped_ev=dropped_ev,
            cve_statuses=cve_statuses,
            reference_details=reference_details,
        )

        return TriageResult(
            finding_id=finding_id,
            artifact_id=art.id,
            output=output,
            kb_hits=kb_hits,
            dropped_references=dropped_refs,
            dropped_evidence=dropped_ev,
            model_run_id=run_rec.run_id,
            examples_used=tuple(examples_used),
        )
    finally:
        if owns:
            db_obj.close()


def _assemble_user_content(art, sanitized: str, kb_hits: list[KbHit]) -> str:
    parts = [
        "=== EVIDENCE METADATA ===",
        f"source_name: {art.source_name}",
        f"content_type: {art.content_type}",
        f"artifact_id: {art.id}",
        "",
        "=== EVIDENCE BODY (sanitized, truncated) ===",
        sanitized,
        "",
    ]
    if kb_hits:
        parts.append("=== KNOWLEDGE BASE HITS (advisory) ===")
        for i, hit in enumerate(kb_hits, 1):
            parts.append(f"{i}. {hit.title} ({hit.topic})")
            parts.append(f"   source: {hit.source_url}")
            parts.append(f"   excerpt: {hit.snippet}")
            parts.append("")
    else:
        parts.append("=== KNOWLEDGE BASE HITS === (none)")
        parts.append("")
    return "\n".join(parts)


def _write_finding_with_audit(
    db: Database,
    *,
    engagement_id: str,
    artifact_id: str,
    output: FindingTriageOutput,
    valid_evidence_ids: list[str],
    kept_references: list[str],
    kb_hits: list[KbHit],
    model_run_id: str,
    actor: str,
    dropped_refs: int,
    dropped_ev: int,
    cve_statuses: dict[str, str],
    reference_details: dict[str, dict],
) -> str:
    """M8-4: write findings + finding_evidence + audit atomically.

    If the audit append fails, the whole transaction rolls back -- the
    finding does not exist without its audit trail. This eliminates the
    window where a finding exists but its triage_completed event was
    never recorded.
    """
    # (batch C) Pre-insert checks and asset linking.
    # 1. Refuse to triage a truncated scan — a partial scan looks like
    #    "fewer findings" but is actually "output dropped after 5 MiB."
    # 2. Derive asset_id from the artifact's source_name by finding the
    #    longest approved_asset.canonical_value whose value appears as a
    #    bounded token in the filename. Reviewer's finding: pipeline was
    #    writing asset_id=NULL, losing the finding->asset relationship.
    _artifact_row = db.connection.execute(
        "SELECT source_name, truncated_output, execution_status FROM artifacts "
        "WHERE id = ? AND engagement_id = ?",
        (artifact_id, engagement_id),
    ).fetchone()
    if _artifact_row is None:
        raise TriageError(
            f"artifact {artifact_id!r} not found in engagement {engagement_id!r}"
        )
    if _artifact_row["truncated_output"]:
        raise TriageError(
            f"artifact {artifact_id!r} ({_artifact_row['source_name']}) "
            f"was truncated during capture. The scan is incomplete; "
            f"refusing to emit a candidate finding from partial output. "
            f"Re-run the scan with a higher output cap, or accept that "
            f"findings may be missing."
        )
    if _artifact_row["execution_status"] != "COMPLETED":
        raise TriageError(
            f"artifact {artifact_id!r} has execution status "
            f"{_artifact_row['execution_status']!r}; incomplete or failed "
            "scanner output cannot be treated as complete triage evidence."
        )

    _asset_id: str | None = None
    if _artifact_row["source_name"]:
        import re as _re
        _sn = _artifact_row["source_name"]
        _assets = db.connection.execute(
            "SELECT id, canonical_value FROM approved_assets "
            "WHERE engagement_id = ? "
            "ORDER BY LENGTH(canonical_value) DESC",
            (engagement_id,),
        ).fetchall()
        for _row in _assets:
            _cv = _row["canonical_value"] or ""
            if not _cv:
                continue
            # Bounded substring: cv must be preceded/followed by
            # start/end or one of _ . / whitespace.
            _pat = r"(?:^|[_.\s/])" + _re.escape(_cv) + r"(?:$|[_.\s/])"
            if _re.search(_pat, _sn):
                _asset_id = _row["id"]
                break

    finding_id = "find_" + uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc).isoformat()
    title = output.summary[:200] if output.summary else "(no summary)"
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO findings
               (id, engagement_id, asset_id, artifact_id, title,
                candidate_category, confidence_hint, lifecycle_state,
                summary, recommended_next_step, missing_evidence_json,
                possible_references_json, kb_hits_json, model_run_id,
                created_at_utc, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'candidate',
                       ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id, engagement_id, _asset_id, artifact_id, title,
                output.candidate_category, output.confidence_hint,
                output.summary, output.recommended_next_step,
                json.dumps(list(output.missing_evidence)),
                json.dumps(kept_references),
                json.dumps([
                    {"entry_id": h.entry_id, "title": h.title,
                     "source_url": h.source_url}
                    for h in kb_hits
                ]),
                model_run_id, now, actor,
            ),
        )
        # (v4.3) Persist per-CVE status. Same transaction as the
        # finding insert — either both land or neither does. Status
        # values match finding_cve_statuses CHECK constraint.
        _cve_now = now
        for _cve_ref, _status in cve_statuses.items():
            conn.execute(
                "INSERT OR REPLACE INTO finding_cve_statuses "
                "(finding_id, cve_id, status, checked_at_utc) "
                "VALUES (?, ?, ?, ?)",
                (finding_id, _cve_ref.upper(), _status, _cve_now),
            )
        for _ref, _detail in reference_details.items():
            conn.execute(
                "INSERT OR REPLACE INTO finding_reference_provenance "
                "(finding_id, original_identifier, reference_type, "
                "validation_status, validation_source, validation_timestamp_utc, "
                "record_id, lookup_outcome, rejection_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (finding_id, _ref, _detail["reference_type"],
                 _detail["status"], _detail["source"],
                 _detail["checked_at_utc"], _detail.get("record_id"),
                 _detail["lookup_outcome"], _detail.get("rejection_reason")),
            )
        for ev_id in valid_evidence_ids:
            conn.execute(
                """INSERT OR IGNORE INTO finding_evidence
                   (id, finding_id, artifact_id, evidence_id,
                    excerpt, created_at_utc)
                   VALUES (?, ?, ?, ?, '', ?)""",
                ("fev_" + uuid.uuid4().hex[:16], finding_id,
                 ev_id, ev_id, now),
            )
        # Audit inside the same transaction (AuditStore.append() uses
        # Database.commit() which is a no-op inside a transaction).
        AuditStore(db).append(
            engagement_id=engagement_id,
            actor=actor,
            event_type="triage_completed",
            decision="candidate",
            details={
                "finding_id": finding_id,
                "artifact_id": artifact_id,
                "model_run_id": model_run_id,
                "kb_hits": len(kb_hits),
                "dropped_references": dropped_refs,
                "dropped_evidence": dropped_ev,
            },
        )
    return finding_id

def _format_examples(examples: list) -> str:
    """Render a list of FewShotExample into the {examples} block text."""
    if not examples:
        return "(no validated examples yet for this engagement)"
    parts: list[str] = []
    for i, ex in enumerate(examples, 1):
        parts.append(f"[Example {i}]")
        parts.append(f"Evidence (truncated): {ex.evidence_snippet}")
        parts.append(f"Operator-validated output: {ex.output_json}")
        parts.append("")
    return "\n".join(parts)

