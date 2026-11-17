-- SPDX-License-Identifier: Apache-2.0
-- Keep the result of each operator initiated NVD lookup, including
-- transient failures that must not be interpreted as invalid CVEs.
CREATE TABLE IF NOT EXISTS cve_sync_attempts (
    attempt_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN
        ('verified','rejected','not_found','transient_error')),
    attempted_at_utc TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail TEXT NOT NULL,
    record_status TEXT
);
CREATE INDEX IF NOT EXISTS idx_cve_sync_attempts_cve
    ON cve_sync_attempts(cve_id, attempted_at_utc);
