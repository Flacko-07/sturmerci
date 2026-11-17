-- SPDX-License-Identifier: Apache-2.0
-- 0014_cve_entries.sql
--
-- Local cache of NVD CVE entries. The pipeline's reference validator
-- consults this table to drop hallucinated CVE IDs. Schema mirrors the
-- fields the validator needs; full NVD record is stored in the raw JSON
-- column for future use.

CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id           TEXT PRIMARY KEY,
    published_utc    TEXT NOT NULL,
    last_modified    TEXT NOT NULL,
    vuln_status      TEXT NOT NULL,
    description      TEXT NOT NULL,
    cvss_score       REAL,
    cvss_severity    TEXT,
    raw_json         TEXT NOT NULL,
    fetched_at_utc   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cve_entries_published
    ON cve_entries(published_utc);
