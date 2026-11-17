-- SPDX-License-Identifier: Apache-2.0
-- Initial schema for Sentinel v1.0.1 (Milestone 2A)

CREATE TABLE engagements (
    id              TEXT PRIMARY KEY,
    platform        TEXT NOT NULL,
    program_name    TEXT NOT NULL,
    policy_url      TEXT,
    state           TEXT NOT NULL DEFAULT 'draft'
                    CHECK (state IN ('draft','scope_review','active','paused','closed')),
    created_at_utc  TEXT NOT NULL,
    updated_at_utc  TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    closed_at_utc   TEXT
);

CREATE INDEX idx_engagements_state ON engagements(state);

CREATE TABLE policy_snapshots (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    policy_hash     TEXT NOT NULL,
    raw_text_path   TEXT NOT NULL,
    reviewed_by     TEXT,
    reviewed_at_utc TEXT,
    created_at_utc  TEXT NOT NULL
);

CREATE TABLE candidate_assets (
    id                 TEXT PRIMARY KEY,
    engagement_id      TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    raw_value          TEXT NOT NULL,
    canonical_value    TEXT NOT NULL,
    asset_type         TEXT NOT NULL,
    discovery_source   TEXT NOT NULL,
    discovered_at_utc  TEXT NOT NULL,
    review_state       TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE approved_assets (
    id                        TEXT PRIMARY KEY,
    engagement_id             TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    raw_value                 TEXT NOT NULL,
    canonical_value           TEXT NOT NULL,
    asset_type                TEXT NOT NULL,
    promoted_from_candidate_id TEXT REFERENCES candidate_assets(id),
    approved_at_utc           TEXT NOT NULL,
    approved_by               TEXT NOT NULL
);

CREATE TABLE approvals (
    approval_id                    TEXT PRIMARY KEY,
    engagement_id                  TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    engagement_state_at_issue      TEXT NOT NULL,
    policy_snapshot_hash           TEXT NOT NULL,
    scope_lock_hash                TEXT NOT NULL,
    target_asset_ids_json          TEXT NOT NULL,
    target_asset_ids_hash          TEXT NOT NULL,
    canonical_hostnames_json       TEXT NOT NULL,
    allowed_ports_json             TEXT NOT NULL,
    allowed_protocols_json         TEXT NOT NULL,
    allowed_http_methods_json      TEXT NOT NULL,
    allowed_path_profile           TEXT NOT NULL,
    operation_profile_id           TEXT NOT NULL,
    tool_name                      TEXT NOT NULL,
    tool_version                   TEXT NOT NULL,
    tool_executable_sha256         TEXT NOT NULL,
    adapter_code_sha256            TEXT NOT NULL,
    manifest_hash                  TEXT NOT NULL,
    egress_profile_id              TEXT NOT NULL,
    normalized_arguments_hash      TEXT NOT NULL,
    request_rate_budget            INTEGER NOT NULL,
    aggregate_request_budget       INTEGER NOT NULL,
    aggregate_byte_budget          INTEGER NOT NULL,
    concurrency_budget             INTEGER NOT NULL,
    aggregate_runtime_budget       INTEGER NOT NULL,
    aggregate_model_token_budget   INTEGER NOT NULL,
    issued_by                      TEXT NOT NULL,
    issued_at_utc                  TEXT NOT NULL,
    expires_at_utc                 TEXT NOT NULL,
    revoked_at_utc                 TEXT,
    renewed_from_approval_id       TEXT
);

CREATE TABLE audit_events (
    seq             INTEGER PRIMARY KEY,
    timestamp_utc   TEXT NOT NULL,
    engagement_id   TEXT NOT NULL,
    actor           TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    decision        TEXT NOT NULL,
    details_json    TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,
    event_hash      TEXT NOT NULL
);

CREATE TABLE model_runs (
    run_id                   TEXT PRIMARY KEY,
    engagement_id            TEXT NOT NULL,
    model_id                 TEXT NOT NULL,
    model_digest             TEXT,
    prompt_template_hash     TEXT NOT NULL,
    sanitized_input_hash     TEXT NOT NULL,
    schema_version           TEXT NOT NULL,
    settings_json            TEXT NOT NULL,
    input_tokens             INTEGER,
    output_tokens            INTEGER,
    duration_sec             REAL NOT NULL,
    outcome                  TEXT NOT NULL,
    retry_count              INTEGER NOT NULL,
    dropped_references       INTEGER NOT NULL,
    created_at_utc           TEXT NOT NULL
);

CREATE TABLE artifacts (
    id                        TEXT PRIMARY KEY,
    engagement_id             TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    source_name               TEXT NOT NULL,
    content_type              TEXT NOT NULL,
    raw_sha256                TEXT NOT NULL,
    sanitized_sha256          TEXT NOT NULL,
    raw_size_bytes            INTEGER NOT NULL,
    sanitized_size_bytes      INTEGER NOT NULL,
    raw_path                  TEXT NOT NULL,
    sanitized_path            TEXT NOT NULL,
    redaction_status          TEXT NOT NULL
                              CHECK (redaction_status IN ('clean','redacted','held_for_review','rejected')),
    unknown_format_triggered  INTEGER NOT NULL DEFAULT 0,
    actor                     TEXT NOT NULL,
    created_at_utc            TEXT NOT NULL
);

CREATE INDEX idx_artifacts_engagement ON artifacts(engagement_id);

CREATE TABLE artifact_redactions (
    id              TEXT PRIMARY KEY,
    artifact_id     TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,
    category        TEXT NOT NULL,
    count           INTEGER NOT NULL,
    decision        TEXT NOT NULL,
    rule_version    TEXT NOT NULL,
    created_at_utc  TEXT NOT NULL
);

CREATE INDEX idx_artifact_redactions_artifact ON artifact_redactions(artifact_id);

CREATE TABLE operational_logs (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    timestamp_utc   TEXT NOT NULL,
    level           TEXT NOT NULL,
    component       TEXT NOT NULL,
    message         TEXT NOT NULL,
    details_json    TEXT NOT NULL
);

CREATE INDEX idx_ops_logs_engagement ON operational_logs(engagement_id);
CREATE INDEX idx_ops_logs_timestamp  ON operational_logs(timestamp_utc);

CREATE TABLE tool_manifests (
    id                      TEXT PRIMARY KEY,
    tool_name               TEXT NOT NULL,
    version                 TEXT NOT NULL,
    executable_path         TEXT NOT NULL,
    executable_sha256       TEXT NOT NULL,
    execution_class         INTEGER NOT NULL,
    network_access          INTEGER NOT NULL,
    allowed_profiles_json   TEXT NOT NULL,
    prohibited_json         TEXT NOT NULL,
    limits_json             TEXT NOT NULL,
    output_format           TEXT NOT NULL,
    manifest_hash           TEXT NOT NULL,
    registered_by           TEXT NOT NULL,
    registered_at_utc       TEXT NOT NULL,
    UNIQUE(tool_name, version)
);
