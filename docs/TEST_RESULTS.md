# Test Results and Verification Plan

## Historical implementation status

The v4.3 regression, privileged egress, and fake-scanner integration suites were run after the implementation. The suites listed below passed with the noted skips. No live NVD synchronization, Ollama triage, real scanner execution, or end-to-end workflow was run. These results do not establish production readiness or deployment-specific security boundaries.

The numbers and live workflow details in the historical section below describe an earlier repository snapshot only. They do not validate this implementation and should not be used as a release or security claim.

## User-reported run — 2026-11-16, after the Gitleaks test fix

The user reran the regression, egress, and adapter-integration commands after
the obsolete registry/manifest setup calls were removed from
`test_refuses_when_engagement_not_active`. The supplied output reports:

- Regression command completed: 726 passed, 8 skipped. Eight integration cases
  skipped because they require root namespace creation.
- Egress command completed: 62 passed, 1 skipped because no forwarding
  container was available at `172.17.0.2:80`.
- Privileged adapter integration command completed: 8 passed.

These are results supplied by the user, not runs performed by the agent. The
egress skip still requires a forwarding target for that specific test.

## Prior-source verification record — 2026-11-15

Commands were run from the repository root in Ubuntu WSL. Egress and adapter integration suites ran as root using `wsl.exe -u root -d Ubuntu`.

```bash
.venv/bin/python -m pytest -q -rs tests/adapters tests/runner tests/policy tests/findings tests/cli tests/l7 tests/llm tests/knowledge tests/triage tests/cvss
.venv/bin/python -m pytest -q -rs tests/egress
.venv/bin/python -m pytest -q -rs tests/adapters/test_*_integration.py
```

- Regression suite: **728 passed, 8 skipped** in 66.12 seconds. Skips were root-required integration cases.
- Egress suite (root): **62 passed, 1 skipped** in 141.66 seconds. The skip required a live container at `172.17.0.2:80`.
- Adapter integration suite (root): **8 passed** in 18.24 seconds. These are test integrations, not real scanner runs.

Still requiring separate operator validation: host-specific Class 0 isolation, live direct-socket/egress checks against the intended deployment, single-CVE NVD sync, local Ollama timeout/triage, real scanner execution, and the authorized end-to-end evidence/report workflow. Use only approved lab targets and approvals, then record command, environment, result, skips, and relevant audit-chain evidence below.

## Historical prior-snapshot record (not current validation)

The following results were recorded in repository documentation before the current implementation and are retained solely as historical context. They must not be interpreted as results for the current code.

- Earlier report: 677 hermetic passed, 8 skipped; 62 egress passed, 1 skipped; 8 privileged adapter reruns; historical end-to-end runs against a lab target and local Ollama.
- Environment and versions for that prior run were recorded in the previous v4 report. They may differ from the current workstation and source tree.

