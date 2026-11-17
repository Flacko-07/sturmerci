# Testing

Release-preparation regression tests were added for XDG/user path overrides,
legacy-path compatibility, packaged SQL migrations, and operator ffuf wordlist
directory overrides, and test-artifact-independent manifest registration.
They have not been executed for this change.

Tests are organized in `tests/` by adapter, runner, policy, findings, CLI, L7,
LLM, knowledge, triage, CVSS, and egress concerns. Some adapter test names end
in `_integration.py`; egress and integration tests may need external programs,
Linux network namespaces, root privileges, or controlled infrastructure.
Inspect test markers and fixtures before running a category.

## Maintainer validation commands

The following commands were used in the prior maintainer validation record;
they are instructions for independent rerun and are not a result for the
current modified tree:

```sh
.venv/bin/python -m pytest -q -rs tests/adapters tests/runner tests/policy tests/findings tests/cli tests/l7 tests/llm tests/knowledge tests/triage tests/cvss
sudo -E .venv/bin/python -m pytest -q -rs tests/egress
sudo -E .venv/bin/python -m pytest -q -rs tests/adapters/test_*_integration.py
```

Run active scanner, live NVD, and Ollama workflows only against explicitly
authorized local infrastructure and after reviewing their exact behavior.
This release-preparation implementation did not run test suites. See
[TEST_RESULTS.md](TEST_RESULTS.md) for historical records; they do not verify
the current changes.

## Release-specific checks still required

- Build wheel and sdist; inspect that SQL migrations are included and that the
  unlicensed default wordlist is excluded until owner rights review is complete.
  The current wheel command is:

  ```sh
  mkdir -p /tmp/sturmer-wheel
  .venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir /tmp/sturmer-wheel .
  ```
- Install the wheel in a clean environment and exercise `sentinel init`,
  migration discovery, user-data path initialization, and adapter registry.
- Run all regression, egress, privileged integration, and authorized live lab
  checks after review.
- Run dependency audit, secret scan, and release-tree privacy review.
