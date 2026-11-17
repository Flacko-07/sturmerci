# SPDX-License-Identifier: Apache-2.0
"""Batch A: test/* profiles must be structurally unreachable from
production code. Runs a fresh subprocess that imports only
builtin_profiles (no conftest).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_production_import_has_no_test_profiles():
    code = (
        "import sentinel.runner.builtin_profiles\n"
        "from sentinel.runner.profiles import all_profiles\n"
        "test_ps = [p for p in all_profiles() if p.startswith('test/')]\n"
        "assert test_ps == [], f'test/* leaked: {test_ps}'\n"
        "print('OK')\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "OK" in r.stdout


def test_production_register_profile_refuses_test_prefix():
    code = (
        "import sentinel.runner.builtin_profiles\n"
        "from sentinel.runner.profiles import (\n"
        "    register_profile, OperationProfile, ProfileError,\n"
        ")\n"
        "try:\n"
        "    register_profile(OperationProfile(\n"
        "        name='test/probe', builder=lambda e,p: [e],\n"
        "        required_params=frozenset(),\n"
        "    ))\n"
        "    raise SystemExit('FAIL: register_profile accepted test/probe')\n"
        "except ProfileError as e:\n"
        "    assert 'reserved' in str(e), str(e)\n"
        "print('OK')\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "OK" in r.stdout


def test_pytest_conftest_provides_test_profiles():
    from sentinel.runner.profiles import get_profile

    p = get_profile("test/echo")
    assert p.name == "test/echo"
