# SPDX-License-Identifier: Apache-2.0
"""E-00 environment probes.

Verifies that the machine still satisfies the prerequisites the egress
design assumes. Runs under root in CI; some checks are unprivileged.

See docs/egress-test-matrix.md §Local environment probes.
"""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest


def test_e00a_unshare_isolates():
    """E-00a: a fresh network namespace has no egress by default."""
    if os.geteuid() != 0:
        pytest.skip("requires root")
    r = subprocess.run(
        ["unshare", "-n", "ping", "-c", "1", "-W", "1", "1.1.1.1"],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode != 0, (
        f"unshare -n should isolate network, but ping succeeded: "
        f"stdout={r.stdout!r} stderr={r.stderr!r}"
    )


def test_e00b_docker_nft_tables():
    """E-00b: Docker's nft tables remain intact (>= 3 table ip*)."""
    if os.geteuid() != 0:
        pytest.skip("requires root")
    r = subprocess.run(
        ["nft", "list", "tables"],
        capture_output=True, text=True, timeout=5,
    )
    assert r.returncode == 0
    count = sum(1 for line in r.stdout.splitlines() if line.startswith("table ip"))
    assert count >= 3, f"expected >= 3 Docker tables, found {count}:\n{r.stdout}"


def test_e00c_dnsmasq_available():
    """E-00c: dnsmasq is on PATH."""
    assert shutil.which("dnsmasq"), "dnsmasq not found on PATH"


def test_e00d_tools_available():
    """All tools the netns module needs are on PATH."""
    for tool in ("ip", "nft", "dnsmasq"):
        assert shutil.which(tool), f"{tool} not found on PATH"
