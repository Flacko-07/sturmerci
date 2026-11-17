# SPDX-License-Identifier: Apache-2.0
"""Process-group kill switch for WSL/Linux. Gate 5 (§12.3).

ECR §13 specified Windows Job Objects; this implementation uses the
POSIX equivalent (start_new_session=True + killpg) because the
orchestrator runs inside WSL2. Document this substitution in
docs/threat-model.md.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time


def run_in_group(args: list[str], **kwargs) -> subprocess.Popen:
    """Spawn a child in its own process group so killpg reaches descendants."""
    return subprocess.Popen(args, shell=False, start_new_session=True, **kwargs)


def kill_group(proc: subprocess.Popen, *, grace_seconds: float = 2.0) -> None:
    """SIGTERM the process group, wait grace period, SIGKILL if still alive."""
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return

    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        # Probe: sending signal 0 raises ProcessLookupError if the group is gone
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
