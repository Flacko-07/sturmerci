-- SPDX-License-Identifier: Apache-2.0
-- 0013_finding_evidence_unique.sql
--
-- One evidence→finding row per pair. Model output can repeat
-- evidence_ids; without a UNIQUE constraint the pipeline writes one
-- row per occurrence (observed: 4x for a single finding).

CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_evidence_pair
    ON finding_evidence (finding_id, evidence_id);
