-- SPDX-License-Identifier: Apache-2.0
-- Active approval budget reservations prevent parallel executions from
-- both spending the same remaining output/request/runtime allowance.
CREATE TABLE IF NOT EXISTS approval_budget_reservations (
    reservation_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL REFERENCES approvals(approval_id) ON DELETE CASCADE,
    requests_reserved INTEGER NOT NULL,
    bytes_reserved INTEGER NOT NULL,
    runtime_reserved_seconds REAL NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_budget_reservations_approval
    ON approval_budget_reservations(approval_id);
