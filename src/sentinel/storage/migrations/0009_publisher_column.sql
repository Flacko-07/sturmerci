-- SPDX-License-Identifier: Apache-2.0
-- M8-2: persist publisher separately.
--
-- knowledge_entries was added in migration 0006 with title/topic/version/
-- license/review_status, but not publisher (a required frontmatter field
-- per docs/knowledge-base-design.md). New ingests populate it; existing
-- rows default to '' until re-ingested (idempotent ingest will update
-- them because the content hash now covers publisher too -- see M8-1).

BEGIN;

ALTER TABLE knowledge_entries
    ADD COLUMN publisher TEXT NOT NULL DEFAULT '';

COMMIT;
