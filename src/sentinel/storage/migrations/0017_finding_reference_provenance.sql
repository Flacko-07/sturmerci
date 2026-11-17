-- SPDX-License-Identifier: Apache-2.0
-- Preserve every model-proposed reference and its validation outcome,
-- including rejected identifiers that are intentionally excluded from
-- findings.possible_references_json.
CREATE TABLE IF NOT EXISTS finding_reference_provenance (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    original_identifier TEXT NOT NULL,
    reference_type TEXT NOT NULL,
    validation_status TEXT NOT NULL
        CHECK (validation_status IN ('verified','unverified','invalid')),
    validation_source TEXT NOT NULL,
    validation_timestamp_utc TEXT NOT NULL,
    record_id TEXT,
    lookup_outcome TEXT NOT NULL,
    rejection_reason TEXT,
    PRIMARY KEY (finding_id, original_identifier)
);
CREATE INDEX IF NOT EXISTS idx_finding_reference_provenance_status
    ON finding_reference_provenance(validation_status);
CREATE INDEX IF NOT EXISTS idx_finding_reference_provenance_identifier
    ON finding_reference_provenance(original_identifier);
