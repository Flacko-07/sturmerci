-- SPDX-License-Identifier: Apache-2.0
-- M7.2c: structured path-prefix authorization.
--
-- allowed_path_profile is retained for the "mode" flag (default vs
-- restricted). allowed_path_prefixes_json carries the actual prefixes
-- that restricted mode enforces. When profile is "default", prefixes is
-- ignored (any path allowed). When profile is non-default, prefixes must
-- be non-empty and path matching uses segment-safe prefix semantics.
--
-- Existing approvals: derive prefixes from the profile column when it
-- looks like a path (starts with /). Otherwise leave empty (which is
-- only valid for default profile; SandboxRunner refuses the mismatch).

BEGIN;

ALTER TABLE approvals
    ADD COLUMN allowed_path_prefixes_json TEXT NOT NULL DEFAULT '[]';

UPDATE approvals
   SET allowed_path_prefixes_json =
       CASE
           WHEN allowed_path_profile LIKE '/%'
               THEN json_array(allowed_path_profile)
           ELSE '[]'
       END
 WHERE allowed_path_profile IS NOT NULL;

COMMIT;
