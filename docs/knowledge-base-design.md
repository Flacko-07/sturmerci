# M8.2 — Knowledge base

**Status:** Implementing
**Date:** 2026-11-14
**Milestone:** M8.2
**Scope:** FTS5-indexed corpus of curated security references.

## 1. Why FTS5, not embeddings

Trade-off table:

| Approach | Index size | Query latency | Semantic recall |
|---|---|---|---|
| FTS5 (SQLite) | ~50 KB per 1 MB corpus | 1-5 ms | Lexical only |
| Local embeddings | ~300 MB model + vectors | 20-50 ms | Semantic |

For a triage tool where the LLM is the semantic layer, FTS5 gives the
LLM candidates and the LLM does the reasoning. FTS5 wins on every
axis that matters here (index size, latency, zero model memory).
Embeddings can be added in M9+ if FTS5 recall proves inadequate in
real assessments — that is the trigger, not "embeddings are modern."

## 2. Corpus organization

Documents live at `knowledge/*.md`. Each has YAML-lite frontmatter:

    ---
    title: Testing for SQL Injection
    topic: web_security
    source_url: https://owasp.org/...
    publisher: OWASP
    version: WSTG-4.2
    license: CC-BY-SA-4.0
    review_status: reviewed
    ---
    [body]

`review_status` is retained as a required legacy frontmatter field for
format compatibility, but ingestion never trusts it. `ingest_directory(db,
knowledge/)` creates an immutable content revision and sets the current
entry to unverified. An independent append-only review record tied to the
revision hash is required before the current revision can appear in search.
Changed content creates a new unreviewed revision. Migration 0016 imports
existing indexed entries as unverified. Use `sentinel knowledge list` to
discover IDs and `sentinel knowledge review` to record a decision.

## 3. Search API

    def search(
        db, query: str, *,
        limit: int = 5,
        filter_tags: list[str] | None = None,
    ) -> list[KbHit]

Returns hits ranked by BM25 (FTS5's default ranking function).
`filter_tags` filters by `knowledge_entries.topic`.

## 4. Query sanitization

User queries pass through:
1. Extract CVE-XXXX-YYYY / CWE-NNN as literal identifiers.
2. Tokenize remaining text on word boundaries.
3. Remove common English stopwords ("how", "to", "test", "for", ...).
4. AND-join the surviving tokens (each quoted to escape FTS5 operators).

Examples:
- `SQL injection` -> `"SQL" AND "injection"`
- `how to test for SQL injection` -> `"SQL" AND "injection"`
- `CVE-2024-1234` -> `"CVE-2024-1234"`
- `CWE-79 XSS` -> `"CWE-79" AND "XSS"`
- empty / all-stopwords -> returns nothing (client should refuse empty)

Rationale for AND (not OR): a security query is usually specific
("SQL injection", not "anything about SQL or injection"). AND gives
precision. BM25 handles ranking within the AND result.

## 5. Seed corpus (M8.2)

6 short documents — enough to prove the pipeline end-to-end:
- Testing for SQL Injection (OWASP WSTG)
- Broken Object Level Authorization (OWASP API Security)
- Cross-Site Scripting (reflected)
- Server-Side Request Forgery (OWASP)
- Security Misconfiguration (OWASP Top 10)
- Sensitive Data Exposure / Cryptography Failures

Not the full corpus. Those 6 cover the most common finding categories
that the M8.3 triage pipeline will be tested against.

## 6. Current provenance boundary

Reviews contain an actor label, timestamp, decision, rationale, revision
ID, and content hash. Ingestion and review labels must differ. The current
single-operator CLI does not authenticate those labels; they provide audit
attribution and do not establish multi-user identity.

## 7. Not in M8.2

- LLM consuming KB results (M8.3 — the triage pipeline calls
  `search()` and feeds hits into prompt context).
- Vector embeddings (M9+ if FTS5 recall proves inadequate).
- A full knowledge curation UI; current review uses the operator CLI.

## 8. Provenance and licensing

Every revision records `source_url`, `publisher`, `version`, `license`,
content hash, ingestion attribution and timestamp. Prior revisions and
review events remain immutable in SQLite. Attribution is preserved;
CC-BY-SA content is acknowledged; no proprietary material is included.
