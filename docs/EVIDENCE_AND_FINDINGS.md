# Evidence and Findings

Evidence ingestion, redaction, integrity metadata, and persistence are
implemented under `src/sentinel/evidence/`. Findings and evidence links are
stored by `src/sentinel/findings/` and the corresponding SQL migrations.
Evidence may contain credentials, personal data, or client information even
after redaction; restrict filesystem access and review exports before sharing.

Triage output is a candidate, not a verified vulnerability. Analysts should
review the source artifact, validate the affected asset and behavior within
authorization, record disposition, and preserve the audit trail. Report
generation is available from the CLI; PDF reporting is not implemented.
