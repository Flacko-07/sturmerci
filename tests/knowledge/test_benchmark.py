# SPDX-License-Identifier: Apache-2.0
"""M8.5 retrieval benchmark.

20 queries with expected top-3 documents. Asserts mean
reciprocal-rank (MRR) >= 0.5 against the 17-document seed
corpus. Corpus is small; threshold is set to what a small,
hand-curated set can reliably achieve. As the corpus grows
with more curation, the threshold should rise.

Run against `knowledge/` in the repo. Does not depend on any
external data.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.knowledge.fts import search
from sentinel.knowledge.ingest import ingest_directory
from sentinel.knowledge.provenance import review_revision
from sentinel.storage.db import Database


REPO_KNOWLEDGE = Path(__file__).resolve().parents[2] / "knowledge"


# (query, expected_titles_top_3_substrings)
# A hit counts if ANY expected substring appears in the returned title.
BENCHMARK: list[tuple[str, list[str]]] = [
    ("SQL injection", ["SQL Injection"]),
    ("SQL injection quote bypass", ["SQL Injection"]),
    ("CWE-89", ["SQL Injection"]),
    ("broken object level authorization", ["Object Level Authorization"]),
    ("BOLA API access control", ["Object Level Authorization"]),
    ("API1:2023", ["Object Level Authorization"]),
    ("reflected cross-site scripting", ["Reflected Cross-Site Scripting"]),
    ("XSS HTML body", ["Reflected Cross-Site Scripting"]),
    ("server side request forgery", ["Server-Side Request Forgery"]),
    ("SSRF callback URL", ["Server-Side Request Forgery"]),
    ("security misconfiguration default credentials", ["Security Misconfiguration"]),
    ("sensitive data exposure cleartext", ["Sensitive Data Exposure"]),
    ("CORS misconfiguration Origin header", ["CORS Misconfiguration"]),
    ("Access-Control-Allow-Credentials", ["CORS Misconfiguration"]),
    ("open redirect Location header", ["Open Redirect"]),
    ("CSRF SameSite cookie", ["Cross-Site Request Forgery"]),
    ("WSTG overview methodology", ["Web Security Testing Guide"]),
    ("NIST SP 800-115 phases", ["NIST SP 800-115"]),
    ("PTES penetration testing standard", ["PTES"]),
    ("passive reconnaissance certificate transparency",
     ["Passive Reconnaissance"]),
    ("API rate limiting resource consumption",
     ["Rate-Limiting", "Rate Limiting"]),
    ("mass assignment autobinding", ["Mass Assignment"]),
    ("JWT authentication weaknesses", ["Authentication"]),
]


@pytest.fixture
def kb_db(tmp_path):
    if not REPO_KNOWLEDGE.exists():
        pytest.skip("knowledge/ directory not present")
    db = Database(tmp_path / "kb.sqlite3")
    processed, errors = ingest_directory(db, REPO_KNOWLEDGE)
    if processed < 10:
        pytest.skip(f"only {processed} docs ingested; benchmark needs corpus")
    assert errors == 0, f"{errors} docs failed to ingest"
    # Imported corpus frontmatter is untrusted. This benchmark explicitly
    # approves the fixture revisions so retrieval exercises the reviewed-only
    # search path without weakening production ingestion semantics.
    entries = db.connection.execute(
        "SELECT id FROM knowledge_entries ORDER BY id"
    ).fetchall()
    for entry in entries:
        review_revision(
            db, entry["id"], reviewer="benchmark-reviewer",
            decision="approved", rationale="benchmark fixture review",
        )
    yield db
    db.close()


def _reciprocal_rank(query: str, expected: list[str], limit: int = 3) -> float:
    """Return 1/rank of first hit whose title contains any expected
    substring, or 0 if none in top-limit."""
    hits = search(kb_db_global[0], query, limit=limit)
    for i, hit in enumerate(hits, 1):
        for exp in expected:
            if exp.lower() in hit.title.lower():
                return 1.0 / i
    return 0.0


# Module-level holder because pytest fixture indirection with parameterized
# tests is simpler this way. Populated by the fixture.
kb_db_global: list[Database] = []


@pytest.fixture(autouse=True)
def _install_kb(kb_db):
    kb_db_global[:] = [kb_db]
    yield
    kb_db_global.clear()


@pytest.mark.parametrize("query,expected", BENCHMARK)
def test_benchmark_query_finds_expected_doc(query, expected):
    """Each query must find an expected doc in the top 3."""
    hits = search(kb_db_global[0], query, limit=3)
    if not hits:
        pytest.fail(f"query {query!r} returned no hits")
    titles = [h.title for h in hits]
    matched = any(
        exp.lower() in t.lower()
        for t in titles for exp in expected
    )
    assert matched, (
        f"query {query!r} did not find expected {expected} in top 3. "
        f"Got: {titles}"
    )


def test_benchmark_mean_reciprocal_rank():
    """Aggregate MRR across benchmark queries must be >= 0.5.

    0.5 is a floor, not a goal. Corpus is 17 docs; as curation grows,
    raise the threshold. Below 0.5 means the retrieval is not
    reliable enough to feed LLM context.
    """
    scores = []
    for query, expected in BENCHMARK:
        scores.append(_reciprocal_rank(query, expected))
    mrr = sum(scores) / len(scores)
    assert mrr >= 0.5, (
        f"MRR {mrr:.3f} below 0.5 threshold. "
        f"Per-query: {list(zip([q for q,_ in BENCHMARK], scores))}"
    )


# --- M8.5 expanded corpus queries (all 14 domains) ---

BENCHMARK_NEW_DOMAINS: list[tuple[str, list[str]]] = [
    ("TCP three-way handshake port states", ["TCP Fundamentals"]),
    ("TLS protocol downgrade weak cipher", ["TLS Configuration"]),
    ("AWS IAM role user permission policy", ["AWS IAM"]),
    ("S3 bucket public access misconfig", ["Storage Misconfiguration"]),
    ("CVE identifier CVSS vector severity", ["CVE Identifiers"]),
    ("CWE weakness enumeration top 25", ["Common Weakness Enumeration"]),
    ("MITRE ATT&CK technique tactic", ["MITRE ATT&CK"]),
    ("indicators of compromise IoC hash", ["Indicators of Compromise"]),
    ("Active Directory domain Kerberos", ["Active Directory"]),
    ("Windows UAC access token privilege", ["Windows Privilege Model"]),
    ("Linux capability cap_sys_admin setuid", ["Linux Permissions"]),
    ("systemd hardening ProtectSystem PrivateTmp", ["Linux Service"]),
    ("MASVS mobile verification", ["MASVS"]),
    ("Android iOS sandbox threat model", ["Android vs iOS"]),
    ("WPA2 WPA3 Wi-Fi WPS security", ["Wi-Fi Security"]),
    ("Bluetooth LE pairing GATT", ["Bluetooth Low Energy"]),
    ("evidence hash chain of custody", ["Digital Evidence Handling"]),
    ("log analysis authentication event", ["Log Analysis"]),
    ("false positive triage pattern", ["Validated Triage Patterns"]),
]


@pytest.mark.parametrize("query,expected", BENCHMARK_NEW_DOMAINS)
def test_benchmark_new_domain_query(query, expected):
    """M8.5: each newly-curated domain answers a representative query."""
    hits = search(kb_db_global[0], query, limit=3)
    if not hits:
        pytest.fail(f"query {query!r} returned no hits")
    titles = [h.title for h in hits]
    matched = any(
        exp.lower() in t.lower()
        for t in titles for exp in expected
    )
    assert matched, (
        f"query {query!r} did not find expected {expected} in top 3. "
        f"Got: {titles}"
    )


def test_benchmark_full_mrr():
    """Combined MRR across original + new-domain benchmarks."""
    all_queries = list(BENCHMARK) + list(BENCHMARK_NEW_DOMAINS)
    scores = [_reciprocal_rank(q, e) for q, e in all_queries]
    mrr = sum(scores) / len(scores)
    assert mrr >= 0.5, (
        f"combined MRR {mrr:.3f} below 0.5. "
        f"Failing queries: {[(q, s) for (q, _), s in zip(all_queries, scores) if s == 0]}"
    )
