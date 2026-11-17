# SPDX-License-Identifier: Apache-2.0
"""FTS5 knowledge base tests. No root needed."""
from __future__ import annotations

import pytest

from sentinel.knowledge.fts import search, _sanitize_query
from sentinel.knowledge.ingest import (
    parse_document, ingest_file, ingest_directory, IngestError,
)
from sentinel.storage.db import Database
from sentinel.knowledge.provenance import review_revision, KnowledgeReviewError


DOC_TEMPLATE = """---
title: {title}
topic: {topic}
source_url: {url}
publisher: Test
version: "1.0"
license: CC-BY-SA-4.0
review_status: reviewed
---
{body}
"""


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "sentinel.sqlite3")
    yield d
    d.close()


@pytest.fixture
def seeded_db(db, tmp_path):
    docs = [
        ("SQL Injection Guide", "web_security", "https://test/sqli",
         "SQL injection lets an attacker alter a database query via "
         "unsafe parameter interpolation. Test by injecting quote "
         "characters and observing error responses."),
        ("Broken Object Level Authorization", "api_security",
         "https://test/bola",
         "BOLA occurs when API endpoints accept object identifiers "
         "without verifying the caller is authorized to access them."),
        ("Server Side Request Forgery", "web_security", "https://test/ssrf",
         "SSRF lets an attacker control where the server fetches a URL. "
         "Test by supplying a callback URL and observing the request "
         "from the target."),
    ]
    for title, topic, url, body in docs:
        path = tmp_path / f"doc_{url.rsplit('/', 1)[1]}.md"
        path.write_text(DOC_TEMPLATE.format(
            title=title, topic=topic, url=url, body=body,
        ))
        entry_id = ingest_file(db, path, ingested_by="curator")
        review_revision(db, entry_id, reviewer="reviewer",
                        decision="approved", rationale="fixture reviewed")
    return db


def test_sanitize_empty_returns_empty():
    assert _sanitize_query("") == ""
    assert _sanitize_query("   ") == ""


def test_sanitize_removes_stopwords():
    assert _sanitize_query("how to test for SQL injection") == (
        '"sql" AND "injection"'
    )


def test_sanitize_preserves_cve():
    assert _sanitize_query("CVE-2024-12345") == '"CVE-2024-12345"'


def test_sanitize_preserves_cwe():
    assert _sanitize_query("CWE-79 XSS") == '"CWE-79" AND "xss"'


def test_sanitize_quotes_fts5_operator_tokens():
    # FTS5 operators in user input must be treated as literals.
    # 'a'/'b' single-char are dropped, 'or' is stopword -> empty.
    # Use tokens that survive the filter to prove the property.
    assert _sanitize_query("sql NOT injection") == (
        '"sql" AND "not" AND "injection"'
    )
    assert _sanitize_query("ssrf and curl") == '"ssrf" AND "curl"'

def test_sanitize_all_stopwords_falls_back():
    assert _sanitize_query("the and") == ""


def test_parse_document_valid(tmp_path):
    path = tmp_path / "x.md"
    path.write_text(DOC_TEMPLATE.format(
        title="Test Title", topic="test", url="https://x/y",
        body="Body content here.",
    ))
    meta, body = parse_document(path.read_text())
    assert meta["title"] == "Test Title"
    assert meta["topic"] == "test"
    assert "Body content here." in body


def test_parse_document_missing_frontmatter():
    with pytest.raises(IngestError, match="must start with"):
        parse_document("no frontmatter here")


def test_parse_document_missing_field():
    text = "---\ntitle: X\ntopic: y\nsource_url: https://x\n---\nbody\n"
    with pytest.raises(IngestError, match="missing required"):
        parse_document(text)


def test_parse_document_empty_body():
    text = (
        "---\ntitle: X\ntopic: y\nsource_url: https://x\n"
        "publisher: P\nversion: v1\nlicense: L\nreview_status: reviewed\n"
        "---\n\n"
    )
    with pytest.raises(IngestError, match="body is empty"):
        parse_document(text)


def test_ingest_writes_entries_and_fts(tmp_path, db):
    path = tmp_path / "doc.md"
    path.write_text(DOC_TEMPLATE.format(
        title="SQL Injection", topic="web_security",
        url="https://test/sqli", body="SQL injection content here.",
    ))
    entry_id = ingest_file(db, path)
    assert entry_id.startswith("kb_")
    entry = db.connection.execute(
        "SELECT title, topic FROM knowledge_entries WHERE id = ?",
        (entry_id,),
    ).fetchone()
    assert entry["title"] == "SQL Injection"
    revision_id = db.connection.execute(
        "SELECT current_revision_id FROM knowledge_entries WHERE id = ?",
        (entry_id,),
    ).fetchone()["current_revision_id"]
    fts_row = db.connection.execute(
        "SELECT entry_id FROM knowledge_fts WHERE entry_id = ?",
        (revision_id,),
    ).fetchone()
    assert fts_row is not None


def test_ingest_is_idempotent(tmp_path, db):
    path = tmp_path / "doc.md"
    path.write_text(DOC_TEMPLATE.format(
        title="X", topic="t", url="https://u/x", body="body",
    ))
    id1 = ingest_file(db, path)
    id2 = ingest_file(db, path)
    assert id1 == id2
    count = db.connection.execute(
        "SELECT COUNT(*) FROM knowledge_entries"
    ).fetchone()[0]
    assert count == 1


def test_ingest_updates_when_content_changes(tmp_path, db):
    path = tmp_path / "doc.md"
    path.write_text(DOC_TEMPLATE.format(
        title="X", topic="t", url="https://u/x", body="original body",
    ))
    entry_id = ingest_file(db, path)
    review_revision(db, entry_id, reviewer="reviewer",
                    decision="approved", rationale="initial review")
    path.write_text(DOC_TEMPLATE.format(
        title="X", topic="t", url="https://u/x", body="updated body",
    ))
    ingest_file(db, path)
    assert search(db, "updated") == []
    assert len(search(db, "original")) == 0
    review_revision(db, entry_id, reviewer="reviewer",
                    decision="approved", rationale="updated revision reviewed")
    assert len(search(db, "updated")) == 1


def test_search_finds_sqli(seeded_db):
    hits = search(seeded_db, "SQL injection")
    assert len(hits) >= 1
    assert any("SQL" in h.title for h in hits)


def test_search_finds_bola(seeded_db):
    hits = search(seeded_db, "object level authorization")
    assert len(hits) >= 1
    assert any("Object Level Authorization" in h.title for h in hits)


def test_search_finds_ssrf(seeded_db):
    hits = search(seeded_db, "server side request forgery")
    assert len(hits) >= 1
    assert any("Forgery" in h.title for h in hits)


def test_search_irrelevant_returns_empty(seeded_db):
    assert search(seeded_db, "kubernetes helm chart") == []


def test_search_filters_by_topic(seeded_db):
    hits = search(seeded_db, "object", filter_tags=["api_security"])
    assert len(hits) >= 1
    assert all(h.topic == "api_security" for h in hits)
    hits = search(seeded_db, "SSRF", filter_tags=["api_security"])
    assert len(hits) == 0


def test_search_limit(seeded_db):
    # 'attacker' appears in both the SQL injection and SSRF
    # document bodies. Unbounded search returns >= 2; limit=1
    # truncates to 1.
    all_hits = search(seeded_db, "attacker")
    assert len(all_hits) >= 2
    limited = search(seeded_db, "attacker", limit=1)
    assert len(limited) == 1

def test_search_empty_query_returns_empty(seeded_db):
    assert search(seeded_db, "") == []
    assert search(seeded_db, "   ") == []


def test_search_returns_snippet(seeded_db):
    hits = search(seeded_db, "SQL injection")
    assert len(hits) >= 1
    assert any("<<" in h.snippet for h in hits)


def test_ingest_directory_batch(tmp_path, db):
    for i in range(3):
        (tmp_path / f"doc{i}.md").write_text(DOC_TEMPLATE.format(
            title=f"Doc {i}", topic="test",
            url=f"https://test/doc{i}", body=f"body number {i}",
        ))
    processed, errors = ingest_directory(db, tmp_path)
    assert processed == 3
    assert errors == 0


def test_ingest_directory_skips_bad(tmp_path, db):
    (tmp_path / "good.md").write_text(DOC_TEMPLATE.format(
        title="X", topic="t", url="https://test/x", body="body",
    ))
    (tmp_path / "bad.md").write_text("not a valid document")
    processed, errors = ingest_directory(db, tmp_path)
    assert processed == 1
    assert errors == 1


def test_draft_documents_not_searchable(tmp_path, db):
    """M8-P0-C: drafts must not appear in search results."""
    (tmp_path / "draft.md").write_text(DOC_TEMPLATE.format(
        title="Draft X", topic="t", url="https://test/draft",
        body="draft only content marked confidential",
    ).replace("review_status: reviewed", "review_status: draft"))
    ingest_file(db, tmp_path / "draft.md")
    # Row exists in DB
    entry = db.connection.execute(
        "SELECT review_status FROM knowledge_entries"
    ).fetchone()
    assert entry["review_status"] == "unverified"
    # But not returned by search
    assert search(db, "confidential") == []
    assert search(db, "draft") == []


def test_reviewed_documents_are_searchable(tmp_path, db):
    """Sanity: reviewed docs still appear (filter isn't over-broad)."""
    (tmp_path / "ok.md").write_text(DOC_TEMPLATE.format(
        title="Reviewed X", topic="t", url="https://test/ok",
        body="reviewed content",
    ))
    ingest_file(db, tmp_path / "ok.md")
    entry_id = db.connection.execute(
        "SELECT id FROM knowledge_entries"
    ).fetchone()[0]
    review_revision(db, entry_id, reviewer="reviewer",
                    decision="approved", rationale="reviewed fixture")
    hits = search(db, "reviewed")
    assert len(hits) == 1


# --- M8-1: metadata-only changes are re-ingested ---

def test_m8p01_metadata_change_updates_row(tmp_path, db):
    """Changing only metadata (not body) must trigger an update."""
    path = tmp_path / "doc.md"
    path.write_text(DOC_TEMPLATE.format(
        title="Original Title", topic="t", url="https://test/x",
        body="unchanged body content",
    ))
    ingest_file(db, path)
    orig = db.connection.execute(
        "SELECT title FROM knowledge_entries"
    ).fetchone()["title"]
    assert orig == "Original Title"

    # Change only the title
    path.write_text(DOC_TEMPLATE.format(
        title="Updated Title", topic="t", url="https://test/x",
        body="unchanged body content",
    ))
    ingest_file(db, path)
    updated = db.connection.execute(
        "SELECT title FROM knowledge_entries"
    ).fetchone()["title"]
    assert updated == "Updated Title", (
        f"metadata update ignored: still {updated!r}"
    )


# --- M8-2: publisher persisted ---

def test_m8p02_publisher_persisted(tmp_path, db):
    """Publisher from frontmatter must be written to knowledge_entries."""
    path = tmp_path / "doc.md"
    path.write_text(DOC_TEMPLATE.format(
        title="X", topic="t", url="https://test/x", body="body",
    ))
    ingest_file(db, path)
    row = db.connection.execute(
        "SELECT publisher FROM knowledge_entries"
    ).fetchone()
    assert row is not None
    # DOC_TEMPLATE has publisher: Test
    assert row["publisher"] == "Test"


def test_frontmatter_cannot_self_approve(tmp_path, db):
    path = tmp_path / "self-approved.md"
    path.write_text(DOC_TEMPLATE.format(
        title="Untrusted", topic="t", url="https://test/untrusted",
        body="should not enter model context",
    ))
    entry_id = ingest_file(db, path, ingested_by="operator")
    assert search(db, "model context") == []
    with pytest.raises(KnowledgeReviewError, match="differ from ingested_by"):
        review_revision(db, entry_id, reviewer="operator",
                        decision="approved", rationale="self approval")
    assert search(db, "model context") == []


def test_review_is_bound_to_immutable_revision(tmp_path, db):
    path = tmp_path / "revision.md"
    path.write_text(DOC_TEMPLATE.format(
        title="Revision", topic="t", url="https://test/revision",
        body="original approved content",
    ))
    entry_id = ingest_file(db, path, ingested_by="curator")
    review_revision(db, entry_id, reviewer="reviewer",
                    decision="approved", rationale="reviewed")
    assert search(db, "original approved")
    path.write_text(DOC_TEMPLATE.format(
        title="Revision", topic="t", url="https://test/revision",
        body="changed unreviewed content",
    ))
    ingest_file(db, path, ingested_by="curator")
    assert search(db, "original approved") == []
    assert search(db, "changed unreviewed") == []


# --- M8.5: recursive ingest ---

def test_ingest_directory_recurses_into_subdirs(tmp_path, db):
    """Nested knowledge/<topic>/*.md files must be ingested."""
    (tmp_path / "web_security").mkdir()
    (tmp_path / "api_security").mkdir()
    (tmp_path / "web_security" / "sqli.md").write_text(DOC_TEMPLATE.format(
        title="SQL Injection", topic="web_security",
        url="https://test/sqli", body="SQL injection content",
    ))
    (tmp_path / "api_security" / "bola.md").write_text(DOC_TEMPLATE.format(
        title="BOLA", topic="api_security",
        url="https://test/bola", body="Object level authorization content",
    ))
    processed, errors = ingest_directory(db, tmp_path)
    assert processed == 2
    assert errors == 0
    assert search(db, "SQL injection") == []
    entry_ids = db.connection.execute(
        "SELECT id FROM knowledge_entries "
        "WHERE source_url IN (?, ?) ORDER BY source_url",
        ("https://test/sqli", "https://test/bola"),
    ).fetchall()
    for row in entry_ids:
        review_revision(
            db, row["id"], reviewer="recursive-ingest-reviewer",
            decision="approved", rationale="reviewed recursive fixture",
        )
    hits = search(db, "SQL injection")
    assert len(hits) == 1
    assert "SQL" in hits[0].title
