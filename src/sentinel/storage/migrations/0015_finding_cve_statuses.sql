-- SPDX-License-Identifier: Apache-2.0
-- 0015_finding_cve_statuses.sql
--
-- Persist the per-CVE validation status alongside each finding.
-- Reviewer's v4.2 finding: pipeline calls resolve_and_filter() without
-- the cve_statuses out-param, so the status of each retained CVE is
-- lost after triage. Operator cannot query "which findings reference
-- unverified CVEs" without re-running the validator.
--
-- One row per (finding, CVE). Status values match refs.CveStatus:
--   'verified'   — cache hit, vuln_status != INVALID
--   'unverified' — cache miss, no explicit negative
--   'invalid'    — cache hit with vuln_status=INVALID (rare; the
--                  validator drops these from the finding, but the row
--                  is kept here for audit — "this was checked and
--                  dropped" is distinct from "this was never seen")

CREATE TABLE IF NOT EXISTS finding_cve_statuses (
    finding_id     TEXT NOT NULL
                   REFERENCES findings(id) ON DELETE CASCADE,
    cve_id         TEXT NOT NULL,
    status         TEXT NOT NULL
                   CHECK (status IN ('verified','unverified','invalid')),
    checked_at_utc TEXT NOT NULL,
    PRIMARY KEY (finding_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_cve_statuses_cve
    ON finding_cve_statuses(cve_id);
CREATE INDEX IF NOT EXISTS idx_finding_cve_statuses_status
    ON finding_cve_statuses(status);
