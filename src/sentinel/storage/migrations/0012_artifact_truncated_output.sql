-- SPDX-License-Identifier: Apache-2.0
-- 0012_artifact_truncated_output.sql
--
-- Store whether a scanner's stdout was truncated by run_captured()'s
-- 5-MiB cap. The pipeline refuses to triage an incomplete scan — a
-- truncated nmap/gitleaks/semgrep/trivy/bandit/exiftool result looks
-- like "fewer findings" but actually means "the rest was dropped."
-- Emitting a candidate finding from partial output is a false negative
-- with extra steps.

ALTER TABLE artifacts
    ADD COLUMN truncated_output INTEGER NOT NULL DEFAULT 0;
