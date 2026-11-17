-- SPDX-License-Identifier: Apache-2.0
-- M8.2: searchable knowledge base.
--
-- Creates the metadata table AND the FTS5 virtual index. Prior to this
-- migration, neither existed -- the M8.2 design doc assumed
-- knowledge_entries was added in 0001, but it wasn't. All statements
-- are IF NOT EXISTS so a partial migration can be retried safely.

BEGIN;

CREATE TABLE IF NOT EXISTS knowledge_entries (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    topic           TEXT NOT NULL,
    source_url      TEXT NOT NULL,
    version         TEXT NOT NULL,
    license         TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    review_status   TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    entry_id UNINDEXED,
    title,
    body,
    topic UNINDEXED,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE INDEX IF NOT EXISTS idx_knowledge_entries_source_url
    ON knowledge_entries(source_url);

CREATE INDEX IF NOT EXISTS idx_knowledge_entries_topic
    ON knowledge_entries(topic);

COMMIT;
