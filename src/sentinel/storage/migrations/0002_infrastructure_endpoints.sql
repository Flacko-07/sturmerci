-- SPDX-License-Identifier: Apache-2.0
-- M5.2: separate provider authorization from target scope.
--
-- tool_manifests.infrastructure_endpoints_json: what the TOOL can contact
--   (declared by adapter author, reviewed at registration).
-- approvals.approved_infrastructure_endpoints_json: what the OPERATOR
--   authorized for this engagement.
-- approvals.approved_infrastructure_endpoints_hash: sha256 over sorted
--   list, so any change invalidates the approval.
--
-- Existing rows default to empty -- no providers were authorized
-- pre-M5.2, and no tool declared any. This is the correct default:
-- silence is not authorization.
--
-- Wrapped in BEGIN/COMMIT for atomicity. If any ALTER fails, all three
-- roll back and the migration does not record as applied.

BEGIN;

ALTER TABLE tool_manifests
    ADD COLUMN infrastructure_endpoints_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE approvals
    ADD COLUMN approved_infrastructure_endpoints_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE approvals
    ADD COLUMN approved_infrastructure_endpoints_hash TEXT NOT NULL DEFAULT '';

COMMIT;
