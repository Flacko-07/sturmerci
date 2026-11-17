-- SPDX-License-Identifier: Apache-2.0
-- Preserve each low-level process completion fact independently. The
-- execution_status remains the normalized operator-facing category.
ALTER TABLE artifacts ADD COLUMN stdout_truncated INTEGER NOT NULL DEFAULT 0
    CHECK (stdout_truncated IN (0,1));
ALTER TABLE artifacts ADD COLUMN stderr_truncated INTEGER NOT NULL DEFAULT 0
    CHECK (stderr_truncated IN (0,1));
ALTER TABLE artifacts ADD COLUMN timed_out INTEGER NOT NULL DEFAULT 0
    CHECK (timed_out IN (0,1));
ALTER TABLE artifacts ADD COLUMN terminated INTEGER NOT NULL DEFAULT 0
    CHECK (terminated IN (0,1));
ALTER TABLE artifacts ADD COLUMN process_exit_code INTEGER;
