# Gitleaks 8.30.1 - JSON output schema

Verified against: `tools/gitleaks` 8.30.1 (SHA-256 pinned in tool_manifests)
Fixture: tests/fixtures/gitleaks_repo/config.py
Date verified: 2026-11-13

Output format: JSON array (top-level `[` ... `]`).
Empty scan: `[]`.
With findings: array of objects, one per match.

## Field schema

| Field | Type | Notes |
|---|---|---|
| Author | str | empty when --no-git |
| Commit | str | empty when --no-git |
| Date | str | empty when --no-git |
| Description | str | human-readable rule description |
| Email | str | empty when --no-git |
| EndColumn | int | |
| EndLine | int | |
| Entropy | float | Shannon entropy of the secret |
| File | str | path as passed in --source (relative or absolute) |
| Fingerprint | str | `file:rule:line` composite |
| Match | str | matched context; literal `REDACTED` when --redact used |
| Message | str | empty when --no-git |
| RuleID | str | e.g. private-key, generic-api-key, aws-access-token, github-pat |
| Secret | str | detected secret; literal `REDACTED` when --redact used |
| StartColumn | int | |
| StartLine | int | |
| SymlinkFile | str | only non-empty when a symlink was followed |
| Tags | list[str] | rule tags; may be empty |

## Verified properties (2026-11-13)

- `Secret` is always exactly the literal string `REDACTED` when
  `--redact` is used. Verified across all five findings.
- `Match` is **context-preserving**: it retains surrounding match
  context and, for some rules (e.g. `github-pat`), the last 4
  characters of the secret as a fingerprint. Examples observed:
    - `"AWS_SECRET_ACCESS_KEY = \"REDACTED\""`  (fully collapsed)
    - `"...B_TOKEN = \"REDACTEDkP4\""`  (4-char suffix preserved)
    - `"...CCESS_KEY_ID = \"REDACTED"`  (partial context)
  Sentinel collapses the suffix via the `redacted_suffix` rule in
  `sentinel.evidence.redact` before persistence. Adapter accepts any
  `Match` containing `REDACTED`; rejects only when the marker is absent.
- `--exit-code 0` returns exit 0 even with findings.
- `--no-git` scans a plain directory (no commit history required).
- `--no-banner` suppresses the ASCII banner so stderr is parseable.
- `File` paths mirror the value passed to `--source`.
- `-v` writes findings to stderr AND the JSON report file. The adapter
  relies on the report file, not stderr.
- `generic-api-key` may fire twice on the same line when two rules match
  (observed at line 17 for ghp_9fK2mN8... which matched both
  `generic-api-key` and `github-pat`). Adapter must not deduplicate;
  both are evidence.

## Adapter contract

- Pass absolute path to `--source` for reproducibility.
- Always pass `--redact`.
- Always pass `--exit-code 0`.
- Always pass `--no-git` unless scanning a git repo is explicitly authorized.
- Always pass `--no-banner`.
- Parse the report file as JSON. Validate each finding has every field in
  the table above; reject findings that are missing required fields.
- Reject any finding whose `Secret` is not the literal string `REDACTED`.
  This is a belt-and-braces check against `--redact` silently failing.
- Second-pass redact `Description`, `Match`, and `File` through
  `sentinel.evidence.redact.redact()` before persistence. Tool-level
  redaction is verified, but defense-in-depth does not depend on it.
