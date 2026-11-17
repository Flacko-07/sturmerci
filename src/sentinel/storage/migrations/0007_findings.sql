-- SPDX-License-Identifier: Apache-2.0
-- M8.3: findings + finding_evidence.
--
-- A finding is a hypothesis about a vulnerability, produced by the
-- triage pipeline. It is ALWAYS created in lifecycle_state='candidate'.
-- The model cannot set lifecycle_state higher -- the schema in M8.3
-- enforces this by only ever writing 'candidate' on insert.
--
-- Transitions to 'human_validated', 'report_ready', etc. are later
-- operator actions (not implemented in M8.3).
--
-- asset_id is nullable: triage of a Gitleaks artifact has no approved
-- asset; triage of an httpx artifact does.
--
-- model_run_id is nullable: a triage that fails before the LLM call
-- (e.g. KB-only analysis in a future milestone) would not have one.
-- For M8.3 it is always populated.

BEGIN;

CREATE TABLE IF NOT EXISTS findings (
    id                       TEXT PRIMARY KEY,
    engagement_id            TEXT NOT NULL
                             REFERENCES engagements(id) ON DELETE RESTRICT,
    asset_id                 TEXT
                             REFERENCES approved_assets(id) ON DELETE RESTRICT,
    artifact_id              TEXT NOT NULL
                             REFERENCES artifacts(id) ON DELETE RESTRICT,
    title                    TEXT NOT NULL,
    candidate_category       TEXT NOT NULL,
    confidence_hint          TEXT NOT NULL,
    lifecycle_state          TEXT NOT NULL DEFAULT 'candidate'
                             CHECK (lifecycle_state IN (
                                 'candidate', 'needs_evidence',
                                 'ready_for_review', 'human_validated',
                                 'report_ready', 'submitted',
                                 'resolved', 'duplicate', 'rejected'
                             )),
    summary                  TEXT NOT NULL,
    recommended_next_step    TEXT NOT NULL,
    missing_evidence_json    TEXT NOT NULL DEFAULT '[]',
    possible_references_json TEXT NOT NULL DEFAULT '[]',
    kb_hits_json             TEXT NOT NULL DEFAULT '[]',
    model_run_id             TEXT
                             REFERENCES model_runs(run_id) ON DELETE SET NULL,
    created_at_utc           TEXT NOT NULL,
    created_by               TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_engagement
    ON findings(engagement_id);

CREATE INDEX IF NOT EXISTS idx_findings_lifecycle
    ON findings(lifecycle_state);

CREATE TABLE IF NOT EXISTS finding_evidence (
    id               TEXT PRIMARY KEY,
    finding_id       TEXT NOT NULL
                     REFERENCES findings(id) ON DELETE CASCADE,
    artifact_id      TEXT NOT NULL
                     REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_id      TEXT NOT NULL,
    excerpt          TEXT NOT NULL DEFAULT '',
    created_at_utc   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding
    ON finding_evidence(finding_id);

COMMIT;
