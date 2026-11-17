-- SPDX-License-Identifier: Apache-2.0
-- Immutable knowledge revisions and independent review events.
-- Existing source-declared "reviewed" rows are imported as unreviewed.
BEGIN;

CREATE TABLE knowledge_revisions (
    revision_id TEXT PRIMARY KEY,
    entry_id TEXT NOT NULL REFERENCES knowledge_entries(id),
    title TEXT NOT NULL,
    topic TEXT NOT NULL,
    source_url TEXT NOT NULL,
    publisher TEXT NOT NULL,
    version TEXT NOT NULL,
    license TEXT NOT NULL,
    body TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    ingested_by TEXT NOT NULL,
    ingested_at_utc TEXT NOT NULL
);
CREATE INDEX idx_knowledge_revisions_entry
    ON knowledge_revisions(entry_id, ingested_at_utc);

CREATE TABLE knowledge_reviews (
    review_id TEXT PRIMARY KEY,
    revision_id TEXT NOT NULL REFERENCES knowledge_revisions(revision_id),
    entry_id TEXT NOT NULL REFERENCES knowledge_entries(id),
    content_hash TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved','rejected')),
    reviewer TEXT NOT NULL,
    reviewed_at_utc TEXT NOT NULL,
    rationale TEXT NOT NULL
);
CREATE INDEX idx_knowledge_reviews_revision
    ON knowledge_reviews(revision_id, reviewed_at_utc);

ALTER TABLE knowledge_entries ADD COLUMN current_revision_id TEXT;

-- Preserve the existing indexed body as a revision, but revoke all
-- source-asserted review claims. These rows need explicit operator review.
INSERT INTO knowledge_revisions (
    revision_id, entry_id, title, topic, source_url, publisher,
    version, license, body, content_hash, ingested_by, ingested_at_utc
)
SELECT 'legacy_' || e.id, e.id, e.title, e.topic, e.source_url,
       COALESCE(e.publisher, ''), e.version, e.license, f.body,
       e.content_hash, 'legacy-import', strftime('%Y-%m-%dT%H:%M:%fZ','now')
FROM knowledge_entries e JOIN knowledge_fts f ON f.entry_id = e.id;

UPDATE knowledge_entries
SET current_revision_id = 'legacy_' || id,
    review_status = 'unverified';

DELETE FROM knowledge_fts;
INSERT INTO knowledge_fts (entry_id, title, body, topic)
SELECT revision_id, title, body, topic FROM knowledge_revisions;

CREATE TRIGGER knowledge_revisions_no_update
BEFORE UPDATE ON knowledge_revisions
BEGIN SELECT RAISE(ABORT, 'knowledge revisions are immutable'); END;
CREATE TRIGGER knowledge_revisions_no_delete
BEFORE DELETE ON knowledge_revisions
BEGIN SELECT RAISE(ABORT, 'knowledge revisions are immutable'); END;
CREATE TRIGGER knowledge_reviews_no_update
BEFORE UPDATE ON knowledge_reviews
BEGIN SELECT RAISE(ABORT, 'knowledge reviews are append-only'); END;
CREATE TRIGGER knowledge_reviews_no_delete
BEFORE DELETE ON knowledge_reviews
BEGIN SELECT RAISE(ABORT, 'knowledge reviews are append-only'); END;

COMMIT;
