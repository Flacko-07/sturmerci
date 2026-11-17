# SPDX-License-Identifier: Apache-2.0
"""Bounded sandbox capture preserves partial data on timeout."""

from __future__ import annotations

from io import BytesIO
import subprocess

import pytest

from sentinel.runner.sandbox_runner import _CappedTimeout, _capped_communicate


class _TimedOutProcess:
    def __init__(self):
        self.stdout = BytesIO(b"partial stdout")
        self.stderr = BytesIO(b"partial stderr")

    def wait(self, timeout=None):
        raise subprocess.TimeoutExpired("scanner", timeout)


def test_capped_communicate_keeps_partial_output_when_timed_out():
    proc = _TimedOutProcess()
    with pytest.raises(_CappedTimeout) as caught:
        _capped_communicate(proc, timeout_s=1, max_bytes=1024)
    assert caught.value.output == b"partial stdout"
    assert caught.value.stderr == b"partial stderr"
    assert caught.value.stdout_truncated is False
    assert caught.value.stderr_truncated is False
