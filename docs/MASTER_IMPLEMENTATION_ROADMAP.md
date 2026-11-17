# Master Implementation Roadmap

**Updated:** 2026-11-15 after v4.3 implementation changes.

| Priority | Work package | Code status | Required validation / remaining work |
|---|---|---|---|
| P0 | Trust and evidence integrity | Hash verification in triage/report; atomic release audit; reference provenance | Run targeted regression tests and inspect audit behavior against disposable DB |
| P0 | Execution completeness | Four-state outcomes, bounded capture, timeout partial output and artifact metadata | Run runner/adapter tests; verify timeout and truncation behavior in controlled environment |
| P0 | Class 0 isolation | Fail-closed bubblewrap staging, network namespace isolation, reduced env and separate output | Verify host prerequisites and namespace/ACL boundary; run local scanner tests |
| P0 | Approval binding and budgets | Required Class 3 parameter hash; pre-spawn atomic output/runtime/request reservations | Run approval and concurrent reservation regression tests |
| P0 | Privileged egress/sandbox | Source boundary exists | Operator must run root-capable egress and integration tests in controlled lab; no code change can substitute for this |
| P1 | Knowledge provenance | Immutable revisions, review records tied to hashes, frontmatter self-approval removed, CLI list/review | Review migrated corpus entries; reviewer labels are not authenticated identities |
| P1 | CVE reference validation | Three-state cache validation and sync-attempt records | Operator validates live NVD behavior; no bulk feeds in scope |
| P1 | Local model boundary | Synchronous HTTP timeout, bounded concurrency, timeout/error model-run records | Verify installed Ollama/client behavior; token budget and cross-process control remain open |
| P1 | Reports | Integrity-checked Markdown export | PDF, report signing, and submission remain deferred |
| P2 | Operator workflow | CLI plus module APIs | Authenticated multi-user workflow, program import/review and unified UI remain deferred |
| P3 | Specialized modules | Not in scope | Continue only after lower-level security gates are independently accepted |

## Sequencing

1. Review migrations 0016–0021 and back up any valued database before migration.
2. Run the hermetic regression suites and inspect failures.
3. Run privileged egress and adapter integration suites in a controlled Linux/WSL lab.
4. Verify Class 0 prerequisites and run local scanner tests on the deployment host.
5. Perform permitted NVD, Ollama, and authorized end-to-end checks; record outcomes in `TEST_RESULTS.md`.
6. Resolve any regressions and revisit the open limitations in `TECHNICAL_DEBT.md` before release decisions.

No milestone in this roadmap is marked validated by the implementation work alone.
