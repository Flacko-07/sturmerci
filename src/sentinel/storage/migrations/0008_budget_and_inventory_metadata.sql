-- SPDX-License-Identifier: Apache-2.0
-- M6-03/M6-04/M7-04: clarify budget semantics, persist inventory metadata.
--
-- approval_usage:
--   output_bytes_used       = bytes captured from stdout+stderr (what
--                             approval.aggregate_byte_budget actually
--                             enforces; this is what we can measure)
--   estimated_network_probes = conservative count of probes the adapter
--                             declares it will issue (over-count is safe)
--   bytes_used / requests_used are deprecated -- do not write; kept for
--   backward compat only.
--
-- candidate_assets:
--   discovery_metadata_json = adapter-specific structured detail
--                             (httpx: status/tech/TLS; nmap: will add
--                             service state when that lands)

BEGIN;

ALTER TABLE approval_usage ADD COLUMN output_bytes_used INTEGER NOT NULL DEFAULT 0;
ALTER TABLE approval_usage ADD COLUMN estimated_network_probes INTEGER NOT NULL DEFAULT 0;

UPDATE approval_usage SET output_bytes_used = bytes_used;
UPDATE approval_usage SET estimated_network_probes = requests_used;

ALTER TABLE candidate_assets
    ADD COLUMN discovery_metadata_json TEXT NOT NULL DEFAULT '{}';

COMMIT;
