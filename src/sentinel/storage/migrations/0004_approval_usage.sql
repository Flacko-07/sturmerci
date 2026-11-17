-- SPDX-License-Identifier: Apache-2.0
-- M6.1.1b: aggregate budget tracking.
--
-- The approval carries budget ceilings (requests, bytes, runtime).
-- This table accumulates actual usage per approval so that:
--   - total requests cannot exceed aggregate_request_budget
--   - total bytes cannot exceed aggregate_byte_budget
--   - total runtime cannot exceed aggregate_runtime_budget
-- A rate limit (--max-rate) is not a total budget; this table is.

BEGIN;

CREATE TABLE IF NOT EXISTS approval_usage (
    approval_id          TEXT PRIMARY KEY
                         REFERENCES approvals(approval_id) ON DELETE RESTRICT,
    requests_used        INTEGER NOT NULL DEFAULT 0,
    bytes_used           INTEGER NOT NULL DEFAULT 0,
    runtime_used_seconds REAL NOT NULL DEFAULT 0.0,
    last_updated_utc     TEXT NOT NULL
);

COMMIT;
