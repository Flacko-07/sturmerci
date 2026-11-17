# SPDX-License-Identifier: Apache-2.0
"""Interprocess lock for the egress layer.

Only one ``run_namespace`` may be active per host at a time. The current
design uses a single global nftables table (``inet sentinel``) and a
fixed veth address range (10.99.0.0/30). Two concurrent runs would each
try to install rules into the same table and each would ``nft.remove()``
in its finally block -- whichever exits first silently breaks the other.

Exclusive locking is the correct control until a future revision scopes
nftables and veths per-run.

The lock is held by ``flock`` on a file, so it is released automatically
on process exit or crash -- no stale-lock cleanup is required.
"""

from __future__ import annotations

import fcntl
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DEFAULT_LOCK_PATH = Path("/tmp/sentinel-run.lock")


class LockHeldError(RuntimeError):
    """Another Sentinel run is already active."""


@contextmanager
def run_lock(lock_path: Path = DEFAULT_LOCK_PATH) -> Iterator[None]:
    """Acquire the global Sentinel egress lock, or raise LockHeldError.

    Held for the duration of the context. Released when the file is
    closed, including on process death (kernel auto-releases on close).
    The PID is written for operator diagnostics; do not use it as a
    liveness check -- check the lock itself via try/except.

    (batch-4) Mode invariant: the lock file must be world-writable
    (0666). It is a coordination primitive, not a security boundary.
    Without this, the first ``sudo pytest tests/egress/`` leaves a
    root-owned 0600 file that blocks every subsequent non-root run with
    ``PermissionError: /tmp/sentinel-run.lock``.

    Flow:
      - Create/open with O_RDWR|O_CREAT and mode 0666. O_CREAT is
        ignored when the file exists; only O_RDWR matters then.
      - Best-effort fchmod 0666. Succeeds if we own the file; skipped
        with a warning if we don't (root creating a file the user later
        opens; or the user opening a root-created file).
      - If open fails with EACCES (pre-existing root-owned 0600 from a
        prior run), raise LockHeldError with a recovery instruction.
        This is the only case that isn't auto-healing — it requires a
        one-time ``sudo rm -f /tmp/sentinel-run.lock``.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    # First attempt: open existing or create with 0666.
    fd = None
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o666)
    except FileNotFoundError:
        # Parent gone between mkdir and open — recreate.
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o666)
        except OSError as e2:
            raise LockHeldError(
                f"cannot create lock file {lock_path}: {e2}. "
                f"Manual recovery: sudo rm -f {lock_path}"
            ) from e2
    except PermissionError:
        # Existing file we cannot open. Try unlink+recreate. Root always
        # succeeds on unlink (CAP_FOWNER on /tmp sticky files); non-root
        # only succeeds if they own the file (which means it's 0000 or
        # otherwise hostile).
        try:
            os.unlink(lock_path)
        except FileNotFoundError:
            pass  # race: someone else unlinked; retry creation
        except OSError as unlink_err:
            raise LockHeldError(
                f"cannot open or unlink {lock_path}: {unlink_err}. "
                f"A prior root run left a lock file this user cannot "
                f"recover. Recover once with: sudo rm -f {lock_path}"
            ) from unlink_err
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o666)
        except OSError as e2:
            raise LockHeldError(
                f"cannot create lock file {lock_path} after unlink: {e2}. "
                f"Manual recovery: sudo rm -f {lock_path}"
            ) from e2
    except OSError as e:
        # Any other error (ENOSPC, EROFS, etc.) — surface it.
        raise LockHeldError(f"cannot open lock file {lock_path}: {e}") from e

    if fd is None:
        raise LockHeldError(f"internal error: lock file {lock_path} was not opened")

    # (v3 hardening) Verify the opened fd is a regular file. O_NOFOLLOW
    # rules out symlinks, but a pre-created FIFO or device would still
    # let read/write block or act unexpectedly. fstat on the open fd
    # cannot be raced — we already own the reference.
    try:
        st = os.fstat(fd)
    except OSError as e:
        os.close(fd)
        raise LockHeldError(f"fstat failed on lock fd: {e}") from e
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise LockHeldError(
            f"lock file {lock_path} is not a regular file "
            f"(mode={oct(st.st_mode)}) — refusing. Remove and retry: "
            f"sudo rm -f {lock_path}"
        )

    # Force 0666 regardless of the creating process's umask. Succeeds
    # only if we own the file. On a root-created file, non-root skips
    # this — but root already chmod'd it on creation, so it's 0666.
    try:
        os.fchmod(fd, 0o666)
    except OSError:
        pass

    f = os.fdopen(fd, "r+", closefd=True)
    try:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as e:
            holder = ""
            try:
                f.seek(0)
                holder = f.read().strip()
            except Exception:
                pass
            raise LockHeldError(
                f"another Sentinel run is active "
                f"(lock: {lock_path}, holder pid: {holder or 'unknown'})"
            ) from e
        try:
            f.seek(0)
            f.truncate()
            f.write(str(os.getpid()))
            f.flush()
        except Exception:
            pass
        try:
            yield
        finally:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
    finally:
        f.close()
