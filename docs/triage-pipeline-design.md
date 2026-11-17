# M8.3 — Triage pipeline

**Status:** Implementing
**Date:** 2026-11-14
**Milestone:** M8.3
**Scope:** Evidence -> KB search -> LLM -> persisted candidate finding.

## 1. The pipeline in one diagram

    artifact (sanitized)
        |
        v
    query_builder        <- extracts query from artifact metadata + content
        |
        v
    fts.search()         <- up to N KbHits
        |
        v
    context assembly     <- evidence + KB hits + metadata
        |
        v
    llm.call_structured  <- FindingTriageOutput, model_runs row written
        |
        v
    validate evidence    <- every ev_id must exist in this engagement
    validate references  <- every ref must exist in KB (else dropped)
        |
        v
    findings + finding_evidence rows
        |
        v
    audit event ("triage_completed")

## 2. What the pipeline does NOT do

- **Does not confirm the finding.** Every finding is created with
  `lifecycle_state='candidate'`. Transitions to `human_validated`,
  `report_ready` etc. are later operator actions, out of scope for M8.3.
- **Does not assign severity.** The `FindingTriageOutput` schema has no
  `severity` field. Severity is a human decision made during report
  authoring (M9).
- **Does not call out to the network.** Evidence is local; KB is local;
  LLM is local. All network-capable work already happened in the adapter
  that produced the artifact.

## 3. Evidence ID validation

The model emits `evidence_ids` that must match `^ev_[a-f0-9]{16,64}$`.
The pipeline validates each one against `artifacts` for this engagement:

- If the ID exists and belongs to the engagement: kept.
- If it does not exist (fabricated by the model): **dropped**, count
  recorded in `triage_result.dropped_evidence`.
- If every evidence_id is dropped: the triage **fails**. A finding with
  no evidence is worse than no finding -- it invites confirmation of
  hallucinated output.

This is the defense-in-depth that makes "trust the model" safe: the
model can say anything, but the finding only references artifacts we
can prove existed.

## 4. Reference validation

The model emits `possible_references` constrained by the schema to
CWE/OWASP/MASVS/CVE patterns. The pipeline then calls
`knowledge.refs.resolve_and_filter()`:

- CWE-NNN and CVE-YYYY-NNNN pass structurally (CVE has no bundled DB).
- CWE-NNN must be in `_KNOWN_CWE` -- else dropped.
- WSTG/API/MASVS must be in the respective known set -- else dropped.
- Dropped references are counted, not failed. The finding is still
  written with the surviving references. A triage that references
  CWE-99999 (a fake) is worse than one that references nothing.

## 5. KB query construction

`build_kb_query()` extracts a query in priority order:

1. **CVE / CWE identifiers in content.** If the evidence mentions
   CVE-2024-1234 or CWE-79, that is the query. Exact identifier search
   in KB.
2. **Filename hints.** Known adapter outputs (gitleaks, nmap, httpx,
   subfinder) map to a category query. Files like `sqli.txt` or
   `bola.json` map by substring.
3. **First four significant words** from the content prefix as fallback.

If none of the above produce tokens, the query is empty and search
returns no hits. That is fine: the model still runs, just without KB
context. Empty KB is not a failure, it is a degraded state.

## 6. Prompt assembly

The `TRIAGE_V1` prompt expects `{user_content}`. The pipeline substitutes:

    === EVIDENCE METADATA ===
    source_name: <artifact.source_name>
    content_type: <artifact.content_type>
    artifact_id: <artifact.id>

    === EVIDENCE BODY (sanitized, truncated) ===
    <sanitized content, up to max_evidence_chars>

    === KNOWLEDGE BASE HITS (advisory) ===
    1. <hit.title> (<hit.topic>)
       source: <hit.source_url>
       excerpt: <hit.snippet with << >> markers>
    ...

The KB hits are *advisory*. The model is free to ignore them if the
evidence doesn't match. Nothing in the prompt forces the model to cite
KB hits.

## 7. What the pipeline records

- 1 row in `findings` (lifecycle_state='candidate', model_run_id set).
- 1 row in `finding_evidence` per surviving evidence_id.
- 1 row in `model_runs` (written by `call_structured`, M8.1).
- 1 row in `audit_events` (triage_completed, with kb_hits/dropped counts).

## 8. Tests

Real DB, real artifact ingestion, real KB ingestion. LLM mocked at the
`_ollama_chat` boundary (same pattern as M8.1) so `model_runs` writes
for real and `model_run_id` FK resolves.

- Happy path: 1 finding, N evidence rows, audit event.
- Wrong engagement: TriageError.
- Missing artifact: TriageError.
- Model emits fake evidence_id: dropped, finding written.
- Model emits only fake evidence_ids: TriageError, no finding.
- Model emits fake CWE: dropped, finding written with empty references.
- KB has no hits: pipeline still works, finding written.
- KB query builder: CVE path, filename path, content path.
