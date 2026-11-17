-- SPDX-License-Identifier: Apache-2.0
-- Persist low-level execution completeness beside every ingested artifact.
ALTER TABLE artifacts ADD COLUMN execution_status TEXT NOT NULL DEFAULT 'COMPLETED'
    CHECK (execution_status IN ('COMPLETED','PARTIAL','TIMED_OUT','FAILED'));
ALTER TABLE artifacts ADD COLUMN stdout_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE artifacts ADD COLUMN stderr_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE artifacts ADD COLUMN output_limit_bytes INTEGER NOT NULL DEFAULT 0;
