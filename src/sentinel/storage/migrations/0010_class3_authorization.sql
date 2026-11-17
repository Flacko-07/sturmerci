-- SPDX-License-Identifier: Apache-2.0
-- ECR v1.0.2 Class 3 authorization fields.
--
-- intrusive_authorized: operator affirmatively permitted active
--   exploitation for this approval. Required for execution_class >= 3.
-- lab_environment: engagement is a controlled lab, not a real target.
--   Required for tools whose default behavior can pivot to
--   persistence/C2 (metasploit). For bounty/VDP/client engagements,
--   this must be 0.

BEGIN;

ALTER TABLE approvals
    ADD COLUMN intrusive_authorized INTEGER NOT NULL DEFAULT 0;

ALTER TABLE approvals
    ADD COLUMN lab_environment INTEGER NOT NULL DEFAULT 0;

COMMIT;
