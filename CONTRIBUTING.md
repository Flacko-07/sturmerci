# Contributing

Contributions are welcome after the repository owner configures the GitHub
repository and private security contact. Do not submit credentials, customer
data, engagement evidence, scanner output from real targets, or model weights.

## Development setup

Use Python 3.12 or newer, create a virtual environment, and install the
development extra:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run focused unit tests locally. The complete test categories and the
maintainer's privileged validation commands are documented in
[docs/TESTING.md](docs/TESTING.md). Never use an external target in tests.

## Repository conventions

- Preserve engagement authorization, scope checks, approval binding, evidence
  integrity, audit-chain failure handling, and execution restrictions.
- Add schema changes as a new ordered SQL migration under
  `src/sentinel/storage/migrations/`; do not rewrite migrations already used by
  an installation.
- New adapters must use the production manifest, profile, approval, and
  evidence paths. Document external executables and operation modes in the
  adapter catalog.
- Add regression tests for security-sensitive changes and update all affected
  documentation. Mark tests that were not run in the PR description.
- Add `SPDX-License-Identifier: Apache-2.0` only to first-party source files
  whose provenance is clear. Preserve third-party notices and do not relicense
  knowledge content or vendored tools.

## Pull requests

Explain the change, security impact, migration/backward-compatibility impact,
tests added, tests run, and tests intentionally not run. Do not claim a test
passed unless its exact command was executed against the submitted tree.
