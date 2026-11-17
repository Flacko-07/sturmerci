# SPDX-License-Identifier: Apache-2.0
"""Tests for adapters._helpers — binary digest + bounded capture."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from sentinel.adapters._helpers import (
    BinaryDigestError, CapturedOutput,
    verify_binary_digest, run_captured, run_isolated_scanner,
    execution_status_for_capture,
)


# ====================================================================
# verify_binary_digest
# ====================================================================

def test_verify_binary_digest_ok(tmp_path):
    f = tmp_path / "bin"
    f.write_bytes(b"hello world")
    h = hashlib.sha256(b"hello world").hexdigest()
    verify_binary_digest(str(f), h)  # no raise


def test_verify_binary_digest_mismatch(tmp_path):
    f = tmp_path / "bin"
    f.write_bytes(b"hello world")
    wrong = "0" * 64
    with pytest.raises(BinaryDigestError, match="digest mismatch"):
        verify_binary_digest(str(f), wrong)


def test_verify_binary_digest_missing(tmp_path):
    with pytest.raises(BinaryDigestError, match="not found"):
        verify_binary_digest(str(tmp_path / "nope"), "0" * 64)


# ====================================================================
# run_captured
# ====================================================================

def test_run_captured_happy_path():
    result = run_captured(
        [sys.executable, "-c", "print('hello'); import sys; sys.stderr.write('err\\n')"],
        timeout_seconds=5,
    )
    assert isinstance(result, CapturedOutput)
    assert result.stdout.strip() == "hello"
    assert result.stderr.strip() == "err"
    assert result.returncode == 0
    assert not result.timed_out
    assert not result.truncated_stdout
    assert not result.truncated_stderr


def test_run_captured_nonzero_exit():
    result = run_captured(
        [sys.executable, "-c", "import sys; sys.exit(7)"],
        timeout_seconds=5,
    )
    assert result.returncode == 7
    assert not result.timed_out


def test_run_captured_timeout():
    result = run_captured(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        timeout_seconds=0.5,
    )
    assert result.timed_out is True
    assert result.returncode != 0   # killed -> SIGKILL typically shows as -9


def test_run_captured_stdout_capped():
    # Emit 200 KB, cap at 1 KB
    result = run_captured(
        [sys.executable, "-c",
         "print('x' * 200_000)"],
        timeout_seconds=5,
        max_stdout_bytes=1024,
    )
    assert result.truncated_stdout is True
    assert len(result.stdout) <= 1024


def test_run_captured_stderr_capped():
    result = run_captured(
        [sys.executable, "-c",
         "import sys; sys.stderr.write('e' * 200_000)"],
        timeout_seconds=5,
        max_stderr_bytes=1024,
    )
    assert result.truncated_stderr is True
    assert len(result.stderr) <= 1024


def test_run_captured_rejects_zero_cap():
    with pytest.raises(ValueError, match="max_stdout_bytes"):
        run_captured(
            [sys.executable, "-c", "pass"],
            timeout_seconds=1, max_stdout_bytes=0,
        )
    with pytest.raises(ValueError, match="max_stderr_bytes"):
        run_captured(
            [sys.executable, "-c", "pass"],
            timeout_seconds=1, max_stderr_bytes=0,
        )


def test_run_captured_env_isolated(tmp_path):
    # Verify a passed env replaces the parent env (no accidental inherit)
    result = run_captured(
        [sys.executable, "-c",
         "import os; print(os.environ.get('HELPER_TEST', 'MISSING'))"],
        timeout_seconds=5,
        env={"HELPER_TEST": "yes", "PATH": "/usr/bin:/bin"},
    )
    assert result.stdout.strip() == "yes"


def test_class0_isolation_fails_closed_without_bwrap(tmp_path, monkeypatch):
    monkeypatch.setattr("sentinel.adapters._helpers.shutil.which",
                        lambda _command: None)
    source = tmp_path / "input"
    source.mkdir()
    with pytest.raises(RuntimeError, match="bubblewrap.*required"):
        run_isolated_scanner(
            [sys.executable, "-c", "pass"], input_path=source,
            timeout_seconds=1,
        )


def test_class0_isolation_rejects_symlinked_input(tmp_path, monkeypatch):
    monkeypatch.setattr("sentinel.adapters._helpers.shutil.which",
                        lambda _command: "/usr/bin/bwrap")
    source = tmp_path / "input"
    source.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("not staged")
    (source / "linked.txt").symlink_to(target)
    with pytest.raises(RuntimeError, match="symlinks are refused"):
        run_isolated_scanner(
            [sys.executable, "-c", "pass"], input_path=source,
            timeout_seconds=1,
        )


@pytest.mark.parametrize(
    ("capture", "expected"),
    [
        (CapturedOutput("", "", 0, False, False, False), "COMPLETED"),
        (CapturedOutput("partial", "", 0, False, True, False), "PARTIAL"),
        (CapturedOutput("partial", "", -9, True, False, False), "TIMED_OUT"),
        (CapturedOutput("", "failed", 2, False, False, False), "FAILED"),
    ],
)
def test_capture_execution_status(capture, expected):
    assert execution_status_for_capture(capture) == expected
