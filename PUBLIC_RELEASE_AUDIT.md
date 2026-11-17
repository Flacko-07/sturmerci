# Public Release Audit

Audit date: 2026-11-16. This is a working-tree review, not publication
clearance. The workspace supplied for this task has no `.git` directory.

## A. Code integrity

- Core package and adapter paths are inventoried in
  `docs/REPOSITORY_INVENTORY.md` and `docs/ADAPTER_CATALOG.md`.
- Removed the production dependency on `tests/egress/.release-gate`; the
  in-memory registry is descriptive, while persistent tool manifests remain
  authoritative for executable identity and integrity.
- CLI command names were inspected in `src/sentinel/cli.py`.
- Runtime Python dependencies are declared in `pyproject.toml` and summarized
  in `docs/DEPENDENCY_INVENTORY.md`.
- Full contribution history and historical secrets cannot be assessed without
  Git metadata. Third-party contribution provenance is not proven.

## B. Packaging

- `pyproject.toml` declares PEP 639 SPDX licence metadata with
  `setuptools>=77`, includes SQL migrations and excludes the unlicensed ffuf
  wordlist from package data, and retains the `sentinel` CLI/import names.
- A final wheel was built with `pip wheel --no-deps --no-build-isolation` and
  inspected structurally. It contained 21 SQL migrations, LICENSE, NOTICE,
  THIRD_PARTY_NOTICES.md, and `License-Expression: Apache-2.0`; the ffuf
  wordlist was absent as intended while rights are unclear. Artifact:
  `sturmercyberintelligence-0.1.0-py3-none-any.whl`, SHA-256
  `52ee0022e342a583a74a3ac637b8696a3d6069e0330c940000d85dae063ff880`.
- XDG user-data defaults and explicit `SENTINEL_DB_PATH` /
  `SENTINEL_ENGAGEMENTS_ROOT` overrides are implemented in `paths.py`.
- Installed-wheel runtime behavior, migration discovery, resource access,
  adapter registry availability, and OS permissions remain unvalidated. The
  structural wheel inspection is not runtime installation validation.

## C. Licensing and branding

- Owner-selected root source licence: Apache License 2.0, SPDX `Apache-2.0`.
- Root `LICENSE` is the official full text; first-party Python and SQL source
  files have SPDX headers without invented copyright owners.
- Third-party tools and all knowledge documents remain separately licensed.
- Knowledge files with internal, proprietary-derived, unclear public, or
  specialized terms are recorded in `docs/LICENSING_REVIEW.md` and must be
  excluded until resolved. Tool payloads also require exact provenance and
  redistribution review.
- Product branding is Sturmer Cyber Intelligence. Trademark and reputation
  clearance remains pending. No exclusive ownership/legal clearance claim is
  made. The project is not affiliated with BlackArch Linux.

## D. Documentation

- New overview, inventory, architecture, security, operator, developer,
  licensing, adapter, dependency, testing, and release-audit documents were
  added or updated.
- `docs/DOCUMENTATION_VERIFICATION.md` distinguishes partially verified,
  historical, and owner/legal-review documents. The complete Markdown corpus
  has not been verified against source; that remains a blocker.
- Internal links and claims still require a dedicated full-document/link
  sweep. Owner confirmations are listed in the licensing, branding and
  community files.

## E. Security and private data

- `.gitignore` now covers common credentials, private key formats, local
  databases, engagement/evidence output, caches, environments, logs and model
  weights. Ignore rules do not remove tracked files.
- The working tree currently contains `data/sentinel.sqlite3`,
  `data/benchmark_qwen3_4b.jsonl`, and `engagements/`; these are excluded by
  ignore rules and must not be released without specific review.
- No credential values are reproduced in this audit. A comprehensive secret
  scanner and history scan were not run; history scan is impossible without
  `.git` metadata. Personal-data and scan-evidence review is incomplete.
- Configure a private vulnerability disclosure channel before publication.

## F. Community readiness

- Contribution, conduct, support, security, issue, pull-request, Dependabot,
  and CI scaffolding have been prepared.
- No GitHub repository was created or modified. `<OWNER>` placeholders and
  private disclosure configuration must be completed by the owner.
- Workflows are definitions only and have not run. Review pinned action
  provenance and permissions before enabling them.

## G. Testing and validation

- Regression tests were added for XDG/user path overrides, legacy-path
  compatibility, packaged SQL migrations, and operator ffuf wordlist
  directory overrides, and test-artifact-independent adapter registration.
- The agent did not execute test suites. The user supplied a 2026-11-16
  post-fix regression, egress, and adapter-integration run; its results and
  skips are recorded in `docs/TEST_RESULTS.md`.
- A package wheel was structurally built/inspected, but live scanner, installed
  wheel smoke, and runtime data-path checks were not executed.
- Exact independent commands are in `docs/TESTING.md`; prior results in
  `docs/TEST_RESULTS.md` predate the current modifications.

## H. Remaining blockers

- No Git metadata: contribution history, historical secrets, and tracked-data
  status are unknown.
- Owner must confirm authority to license the first-party contribution set.
- Confirm the source and redistribution rights for
  `config/wordlists/common.txt`; until then it is omitted from wheels and an
  installed ffuf adapter needs an operator-managed wordlist directory.
- Resolve/exclude all knowledge corpus and scanner payloads with unclear
  redistribution rights; complete dependency licence inventory and SBOM.
- Run the independent regression/security/egress/privileged integration and
  authorized local-lab validation on the modified tree.
- Build and inspect the wheel, install it in a clean environment, and validate
  resource and user-data behavior.
- Complete all-Markdown factual review and internal-link validation.
- Configure private vulnerability reporting and confirm GitHub slug ownership.
- Complete trademark and reputation clearance for Sturmer.

## Status

- **Technically prepared for release:** No. Packaging and documentation changes
  are prepared for independent review but have not been built or validated.
- **Legally and operationally cleared for publication:** No. Rights,
  provenance, private disclosure, data, and trademark blockers remain.
