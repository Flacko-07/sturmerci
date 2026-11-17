-- SPDX-License-Identifier: Apache-2.0
-- M6.1.1b: shared infrastructure authorization.
--
-- Default FALSE. Approving a hostname does NOT auto-approve the resolved
-- IP's other tenants. Operator must affirm the program permits scanning
-- the underlying infrastructure before Nmap will run against it.
--
-- httpx (M7) will not require this — HTTP GET inventory is not port
-- scanning. HTTP method/path enforcement is a separate control (M7).

BEGIN;

ALTER TABLE approvals
    ADD COLUMN port_scanning_authorized INTEGER NOT NULL DEFAULT 0;

COMMIT;
