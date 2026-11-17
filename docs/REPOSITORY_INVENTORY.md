# Repository Inventory

This inventory describes the working-tree snapshot inspected on 2026-11-16.
The workspace contains no `.git` directory, so tracked-file status and commit
history cannot be determined here. Runtime behaviour must be checked against
the source, not milestone documents.

## Application source (`src/sentinel/`)

| Path | Responsibility |
|---|---|
| `cli.py` | Typer command-line application and operator workflows. |
| `paths.py` | Default database and engagement filesystem locations. |
| `adapters/` | 18 tool integrations: Bandit, dig, ExifTool, ffuf, Gitleaks, httpx, Metasploit, Nikto, Nmap, Nuclei, SCION, Semgrep, SQLMap, Subfinder, theHarvester, Trivy, WHOIS, and ZAP. |
| `approval/` | Approval state, gatekeeper, budgets, issuance and persistence. |
| `assets/` | Asset and infrastructure inventory persistence. |
| `audit/` | Hash-chained operational audit events and model-run records. |
| `cvss/` | CVSS calculation integration; complete CVSS 4.0 remains deferred. |
| `engagement/` | Engagement lifecycle and persistence. |
| `evidence/` | Evidence ingestion, redaction, integrity and storage. |
| `findings/` | Finding persistence and lifecycle. |
| `knowledge/` | Knowledge ingestion, provenance, FTS, NVD synchronization and reference validation. |
| `l7/` | Application-layer proxy, CA and gatekeeper filtering. |
| `llm/` | Local Ollama client, prompts and few-shot examples. |
| `logging/` | Operational logging helpers. |
| `models/` | Shared data contracts. |
| `netns/` | Linux network namespace, nftables, DNS and lock management. |
| `reporting/` | Report generation; PDF output is not implemented. |
| `runner/` | Descriptive adapter capability metadata, operation profiles, sandbox execution, and kill switch. Persistent tool manifests are authoritative for registered binary identity/integrity; runtime does not depend on test-tree markers. |
| `scope/` | Scope canonicalization and target matching. |
| `storage/` | SQLite database, migration runner and ordered SQL migrations. |
| `tools/` | Tool manifest and registration CLI. |
| `triage/` | Evidence triage and query construction. |

## Other content

- `tests/`: adapter, runner, policy, evidence/findings, CLI, L7, LLM, knowledge,
  triage, CVSS, and egress tests; `tests/egress/` contains privileged/network
  validation material.
- `config/wordlists/`: default ffuf wordlist.
- `knowledge/`: 36 Markdown knowledge documents with per-file provenance and
  licence labels. Several are quarantined for rights review; see
  [Licensing Review](LICENSING_REVIEW.md).
- `tools/`: scanner payloads and Nikto vendor tree. Exclude these payloads
  from public redistribution until exact provenance, version, and rights are
  established. Keep their supplied notices intact.
- `docs/`: implementation designs, operator guide, threat model, test results,
  roadmaps, and audit history. Some are historical or design documents, not
  proof that a feature is present.
- `pyproject.toml`: setuptools project metadata and `sentinel` entry point.
- `.github/`: community templates and automation prepared for maintainer
  review; workflows must be reviewed before enabling.

## Implemented versus deferred

Implemented module families are listed above. Module presence alone does not
prove a tool is installed, operational on a host, or safe for a particular
engagement. Environment-dependent functionality includes Linux namespaces,
nftables, external scanner executables, and local Ollama. Deliberate deferrals
include kernel-level isolation of TLS proxy upstream connections, fully
unprivileged no-network execution for all Class 0 scanners, complete CVSS 4.0,
PDF reporting, and bulk NVD/CWE/CAPEC/ATT&CK ingestion. See
[Technical Debt](TECHNICAL_DEBT.md).

## Sensitive and generated content present in the working tree

The snapshot contains `data/sentinel.sqlite3` and an `engagements/` directory.
These are ignored by `.gitignore` and must not be placed in a release. The
repository itself has no Git metadata here, so this inventory cannot determine
whether they were ever committed or appeared in earlier commits.
