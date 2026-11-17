# Documentation Verification Matrix

Status reflects this release-preparation review, not a blanket claim that every
historical statement has been validated. Source paths are listed where they
were checked. Historical documents, knowledge materials, and vendor manuals
require the additional review noted below.

| Document | Purpose | Source paths inspected | CLI commands verified | Tests inspected | Status | Outstanding corrections |
|---|---|---|---|---|---|---|
| `README.md` | Product overview and entry points | `pyproject.toml`, `cli.py`, subsystem tree, `TECHNICAL_DEBT.md` | Current groups cross-checked in `cli.py` | `TEST_RESULTS.md` only | Partially verified | Recheck after owner selects GitHub URL, rights exclusions, and wheel validation. |
| `docs/REPOSITORY_INVENTORY.md` | Module and content inventory | `src/sentinel/`, `tests/`, `config/`, `knowledge/`, `tools/` paths | N/A | Test tree enumerated | Partially verified | No Git history; source inventory is working-tree-only. |
| `docs/ADAPTER_CATALOG.md` | Adapter module/executable inventory | `src/sentinel/adapters/`, runner and profile paths | Scan group names checked against `cli.py` | Adapter test paths enumerated | Partially verified | Reconcile per-adapter modes and manifest versions against production registry. |
| `docs/ARCHITECTURE.md` | Data flow and trust boundaries | `cli.py`, `runner/`, `netns/`, `approval/`, `evidence/`, `storage/`, `audit/`, `llm/`, `triage/` | Root command flow inspected | Tests not exhaustively mapped | Partially verified | Verify every diagram edge against an installed runtime. |
| `docs/INSTALLATION.md` | Source installation and data locations | `pyproject.toml`, `paths.py`, `storage/db.py`, `cli.py` | `sentinel init` | New path/resource tests written | Partially verified | Build and install a wheel, then validate data initialization. |
| `docs/CONFIGURATION.md` | Current data-path environment variables | `paths.py`, `cli.py` | N/A | New path tests written | Partially verified | Check all scanner/Ollama configuration and document only verified variables. |
| `docs/CLI_REFERENCE.md` | Command index | `src/sentinel/cli.py` | Command decorators inspected | `tests/cli/` inspected by path | Partially verified | Exact options need generated help capture per release. |
| `docs/SECURITY_MODEL.md` | Control and limitation summary | `approval/`, `scope/`, `runner/`, `netns/`, `evidence/`, `audit/`, `llm/` | N/A | Security test paths enumerated | Partially verified | Independent security and host-level verification remains outstanding. |
| `docs/TECHNICAL_DEBT.md` | Open issues and deferrals | Existing source modules and prior `TEST_RESULTS.md` | N/A | Historical results distinguished | Partially verified | Validate all entries against the post-change source. |
| `docs/LICENSING_REVIEW.md` | Apache decision and rights quarantine | source headers, `pyproject.toml`, tools notices, knowledge frontmatter | N/A | N/A | Needs owner/legal review | Contribution authority, knowledge and tool redistribution, SBOM licences. |
| `docs/BRANDING_REVIEW.md` | Selected name and clearance | README, package metadata | N/A | N/A | Needs owner/legal review | Trademark/reputation clearance and repository slug availability. |
| `THIRD_PARTY_NOTICES.md` | Dependency/tool/content notices | `pyproject.toml`, `tools/`, knowledge frontmatter | N/A | N/A | Needs owner/legal review | Exact resolved dependency versions, licences and tool-to-notice mapping. |
| `docs/TEST_RESULTS.md` | Historical validation record | Existing result document only | Commands listed in document | Not rerun for this update | Historical | Re-run current maintainer sweep; do not treat as validation of current edits. |
| Existing design/roadmap docs | Historical design, milestones, subsystem guidance | Not exhaustively reviewed in this pass | Not exhaustively checked | Not exhaustively mapped | Historical / needs review | Reconcile every behavioural claim to current code before publication. |
| `knowledge/**/*.md` | Retrieval content and curated research | Frontmatter licence labels enumerated | N/A | Ingestion tests inspected by path | Needs owner/legal review | Review every source, derivative, attribution and redistribution condition. |
| `tools/**/*.md` and vendor manuals | Third-party install and usage docs | Root `tools/` notices and Nikto attribution samples | N/A | N/A | Needs owner/legal review | Full vendor document and payload rights inventory. |

This matrix is intentionally explicit about incomplete review. It does not
claim every Markdown file has been read or verified. Such review remains a
publication blocker.
