# Knowledge Base — Coverage and Curation Roadmap

**Version:** 1.0.0
**Date:** 2026-11-14
**Milestone:** M8.5

## Current state

36 curated documents across all 14 domains. Every domain has at
least 1 doc; 12 have 2+, 2 have 3-8 (web + api from earlier
seeds).

| Domain | Documents | Notable coverage |
|---|---|---|
| api_security | 4 | BOLA, auth, rate-limit, mass-assignment |
| cloud_security | 2 | AWS IAM, storage misconfig |
| forensics | 2 | evidence handling, log analysis |
| linux_security | 2 | permissions/caps, systemd |
| methodologies | 3 | WSTG, NIST, PTES |
| mobile_security | 2 | MASVS, Android vs iOS |
| network_security | 2 | TCP, TLS |
| our_research | 1 | triage pattern seed |
| reconnaissance | 2 | passive recon, DNS |
| threat_intelligence | 2 | ATT&CK, IoCs |
| vulnerability_intel | 2 | CVE/CVSS, CWE |
| web_security | 8 | SQLi, XSS, SSRF, misconfig, sensitive data, CORS, CSRF, redirect |
| windows_security | 2 | AD basics, privilege model |
| wireless_security | 2 | WiFi, BLE |
| **Total** | **36** | |

## What each document is

Every document is a **curator summary** — a condensed overview
written to serve triage (recognizing what category an observation
falls into, and what to check next), not verbatim reproduction
of the source. Each carries:

- `source_url` — canonical link to the authoritative source.
- `publisher` — who maintains the source.
- `version` — spec/edition the summary reflects.
- `license` — redistribution rights for the summary.
- `review_status` — retained for frontmatter compatibility only. It is
  ignored during ingestion and does not grant retrieval eligibility.

Retrieval eligibility is stored separately in the database. Each current
revision needs an append-only approved review tied to its exact content
hash. Migration 0016 marks all pre-existing entries unverified. Reviewers
are discoverable with `sentinel knowledge list` and use
`sentinel knowledge review`; reviewer labels are not authenticated identity.

The summary explicitly says "consult the source for the canonical
text." Fabricated content (as opposed to curated summary) is
prohibited.

## What is NOT covered

- Per-technique ATT&CK detection procedures.
- Per-CVE exploit paths (NVD integration is M9+).
- Vendor-specific cloud service catalogs (each vendor has
  hundreds of services).
- Wireless/mobile assessment methodology specifics (out of
  v1.0 capability).
- Windows/Mac/Linux per-version hardening baselines.

These gaps are honest and documented so a reviewer can
distinguish "not yet curated" from "overlooked."

## Curation roadmap (M9+)

In priority order:

1. **vulnerability_intel** — single-CVE NVD API lookup and local cache
   now support three-state reference checks; bulk NVD/CWE/CAPEC/ATT&CK
   synchronization remains deferred.
2. **web_security** — expand with per-category WSTG detail
   (currently 8 docs; full expansion is ~30).
3. **api_security** — expand with OWASP API Top 10 detail
   (currently 4).
4. **cloud_security** — add Azure and GCP specifics. Currently
   AWS-weighted.
5. **threat_intelligence** — add defensive technique pages for
   ATT&CK tactics most relevant to assessment-driven findings.
6. **reconnaissance** — add certificate transparency deep-dive,
   passive DNS mechanics.
7. **network_security** — add IPv6 specifics, service hardening.
8. **forensics** — add Windows event log specifics, cloud audit
   log parsing.
9. **methodologies** — expand beyond the three core frameworks.
10. **windows_security**, **linux_security** — add OS-version
    baselines.
11. **mobile_security**, **wireless_security** — when adapters
    are added (M10+).
12. **our_research** — grows organically with engagements.

Corpus size and coverage describe files in the repository. They do not
imply that current database revisions have been reviewed; review state
depends on the local database's immutable review records.

## Retrieval quality

The benchmark (`tests/knowledge/test_benchmark.py`) asserts that
42+ queries return an expected document in the top 3. As curation
expands, the benchmark should expand and the MRR threshold should
rise from 0.5 toward 0.7.

A retrieval failure is a signal to add vocabulary to a
document, not to loosen the query. Query relaxation (AND → OR
fallback) exists at the search layer; benchmark failures at that
layer point to a genuinely missing vocabulary.

## Curation workflow

Adding a document:

1. Write `knowledge/<domain>/<slug>.md` with frontmatter.
2. Add a search query to the benchmark expecting this doc.
3. Run `pytest -q tests/knowledge/`.
4. If the benchmark MRR drops, tighten the new doc's vocabulary
   or add a disambiguating term to the query.

Every document must pass the ingest pipeline (frontmatter
validation, no fabricated content, source URL reachable at
curation time).

## Reviewing the KB

For a security reviewer of Sentinel:

1. Inspect `knowledge/<domain>/` — each doc has a source_url.
   Spot-check 3-4 that the summaries match what the source says.
2. Run the benchmark — demonstrates retrieval works for the
   categories the triage pipeline uses.
3. Check that no doc claims authority ("definitive guide") — they
   are all curator summaries with explicit "consult source"
   language.
4. Confirm `our_research` is seed-only (5 anti-pattern entries),
   not filled with fabricated engagement findings.

## Non-goals

- **Not a replacement for the source.** An engineer using the KB
  should still go to OWASP/NIST/MITRE for the test method. The
  KB accelerates recognition, not exhaustive reading.
- **Not a vulnerability database.** CVE lookups need NVD
  integration (M9).
- **Not a training corpus.** No LM training or fine-tuning
  consumes this content. It is retrieval context for RAG only.
