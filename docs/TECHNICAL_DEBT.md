# Technical Debt and Unresolved Risks

**Updated:** 2026-11-16 for Sturmer public-release preparation.
**Validation state:** `TEST_RESULTS.md` records prior results and the user-reported 2026-11-16 regression, egress, and adapter-integration runs after the Gitleaks test fix. The agent did not execute those suites. Installed-wheel runtime validation, secret/history review, live NVD/Ollama, real-scanner, and end-to-end workflows remain outstanding.

## Implemented in the current source

- CVE references now retain VERIFIED, UNVERIFIED, or INVALID outcomes. Cache misses remain unverified, NVD definitive not-found results are recorded as invalid, and transient lookup errors remain distinguishable. Proposed-reference provenance is stored per finding, including filtered identifiers.
- Triage and report generation verify sanitized evidence bytes against stored SHA-256 and size metadata before use. Evidence release updates and its audit event share one transaction.
- Network and Class 0 scanner captures use bounded output. Results expose COMPLETED, PARTIAL, TIMED_OUT, or FAILED, retain available output on timeout, and persist execution metadata with evidence. CLI scan commands display the status.
- Class 0 scanners use a fail-closed bubblewrap boundary with read-only staged input, separate optional output, UID/GID 65534, reduced environment, and an unshared network namespace. Missing isolation support refuses execution.
- Class 3 operation profiles can require canonical parameter binding to the approval. CLI approval records do not store parameter values in plaintext.
- Aggregate output, runtime, and request budgets are reserved before process launch and settled after execution. Output capture is clamped to remaining byte allowance.
- Ollama HTTP requests use the client timeout synchronously; no detached worker thread is used. Concurrent requests remain bounded, and timeout/error outcomes are recorded.
- Knowledge revisions and review events are immutable/append-only. Source frontmatter cannot approve a revision. Search only returns the current revision when its latest review is approved; CLI provides `knowledge list` and `knowledge review`.
- Production adapter execution no longer consults the test-only egress release marker. Persistent tool manifests remain authoritative for tool identity and integrity; the in-memory registry is descriptive, and Gitleaks verifies its database manifest directly.

The implementation statements above are supported by source inspection and the test results in `TEST_RESULTS.md`. Passing tests do not replace deployment-specific validation.

## Status classifications

- **Implemented and independently tested (historical source state):** the regression suite (728 passed, 8 skipped), privileged egress suite (62 passed, 1 skipped), and fake-scanner adapter integrations (8 passed) are recorded in `TEST_RESULTS.md`. Those results do not cover the current release-preparation edits.
- **Implemented, user-reported regression sweep completed:** XDG/user-data path selection, legacy data-path fallback, packaged migration resources, ffuf wordlist override, and test-artifact-independent registry behavior have coverage in `tests/test_user_paths.py`, `tests/test_packaging_resources.py`, `tests/adapters/test_ffuf_adapter.py`, and `tests/policy/test_gate6.py` / `test_gitleaks_adapter.py`. The user-reported post-fix run is summarized in `TEST_RESULTS.md`; installed-wheel runtime validation remains open.
- **Implemented, awaiting environment-specific validation:** installed-wheel resource discovery, user-data directory initialization, deployment-host namespace behavior, live NVD/Ollama behavior, actual scanner execution, and authorized local-lab workflow.
- **Deliberately deferred:** kernel-level TLS proxy upstream isolation; full Class 0 unprivileged/no-network staging beyond the implemented local boundary; bulk NVD/CWE/CAPEC/ATT&CK feeds; full CVSS 4.0 calculation/report integration; PDF rendering; automated report submission; and authenticated multi-user workflows.
- **Open correctness/security debt:** model-token budget enforcement, authenticated reviewer identity, privileged deployment verification, and complete release provenance/redistribution checks.
- **Open packaging limitation:** the source-checkout ffuf wordlist has no provenance/licence statement and is intentionally omitted from wheels; installed-wheel ffuf use requires an operator-managed `SENTINEL_WORDLIST_DIR` until rights are resolved.
- **Requires owner/legal decision:** confirmation of authority to license all first-party contributions, tool and knowledge redistribution rights, private security contact, repository ownership/slug availability, and Sturmer trademark/reputation clearance.

## Open risks and validation gates

### Privileged egress and namespace behavior

The namespace, nftables, DNS, revocation, proxy and adapter containment paths still require the operator's privileged controlled-lab verification. This implementation does not establish kernel-level egress behavior or WSL2 compatibility.

### Class 0 isolation availability

Bubblewrap user/network namespace support and POSIX ACL tooling are deployment prerequisites. The code refuses the local scanner launch when these boundaries cannot be created. Verify the installed bubblewrap behavior and permissions on the operator's WSL/Linux host. This local namespace is defense-in-depth, not a VM boundary against a kernel exploit.

### Knowledge reviewer identity

Review events bind reviewer labels to exact immutable revision hashes and disallow the same label used for ingestion. Labels are attribution only: the application has no authenticated user/session identity. Do not treat this workflow as multi-user identity proof.

### Budget semantics

Approval request counts are adapter-declared estimates, and byte accounting is captured stdout/stderr, not network traffic. Runtime is capped by the pre-spawn reservation. `aggregate_model_token_budget` is not connected to triage/model calls because no approval context is passed to the model pipeline; enforcement remains open.

### NVD dependency

Single-CVE synchronization requires operator-initiated network access and a reachable NVD API. This implementation does not add bulk NVD/CWE/CAPEC/ATT&CK feeds. Live lookup, rate-limit behavior and cache migration require independent operator validation.

### Ollama dependency

The request boundary uses HTTP client timeouts and a bounded in-process semaphore. It does not terminate a wedged Ollama server process, enforce model token usage against an approval, or provide cross-process concurrency control. Validate the deployed Ollama/client version and timeout behavior independently.

### TLS proxy upstream boundary

The proxy's upstream connection does not have kernel-level isolation.
Proxy use remains lab-restricted. Do not relax that restriction as part of
this implementation.

### Reporting and operator workflow

Safe Markdown reporting is present and checks evidence integrity; PDF generation, report signing, submission, a unified operator UI, and authenticated operator identities remain outside this implementation. Reports are exports for human review and are never submitted automatically.

## Deliberately deferred

- Bulk NVD/CWE/CAPEC/ATT&CK synchronization and rollback workflows.
- Full CVSS 4.0 scoring/report integration. Any existing calculator code
  is not treated as a completed report workflow or expanded by this task.
- Kernel-level isolation of the TLS proxy upstream connection; retain the
  existing lab-only restriction.
- PDF rendering and automated report submission.
- Program-policy import/review UX and a unified Offline/Passive/Active mode manager.
- Multi-user authentication and authorization.
- Enforcement of model-token budgets at the Ollama boundary.
- Kernel/VM isolation for hostile local scanner inputs.

## Migration notes

Migrations 0016–0021 add immutable knowledge provenance, finding reference provenance, CVE sync-attempt records, concurrency-safe approval budget reservations, and artifact execution/capture metadata. Existing knowledge corpus rows are migrated as unverified and need an explicit review before retrieval. Run migration review/backup procedures before applying against valued operator data.

The current source snapshot has no Git metadata. The licensing and branding
review therefore cannot inspect contribution history or prior committed
secrets; see `PUBLIC_RELEASE_AUDIT.md` before considering publication.
