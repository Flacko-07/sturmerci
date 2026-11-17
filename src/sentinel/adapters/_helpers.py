# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for local (Class 0) adapters.

bandit, semgrep, trivy, gitleaks all run a local subprocess via
subprocess.run(capture_output=True). That has three problems the reviewer
identified:

  - no binary digest verification against the manifest
  - unbounded output capture (a misbehaving tool can fill memory)
  - no distinction between "tool succeeded with N findings" and
    "tool crashed / errored / timed out"

This module centralizes the fix so all three adapters use the same
behavior, and future local adapters get it for free.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import threading
import tempfile
from dataclasses import dataclass
from pathlib import Path


DEFAULT_MAX_OUTPUT_BYTES = 5 * 1024 * 1024  # 5 MiB stdout
DEFAULT_MAX_STDERR_BYTES = 1 * 1024 * 1024  # 1 MiB stderr

# (batch B) Minimal environment for local scanner subprocesses. Local
# scanners parse untrusted source code; leaking the parent's full env
# (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, cloud creds, SSH_AUTH_SOCK)
# into a compromised scanner is a real credential exposure.
MINIMAL_SCANNER_ENV_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "LC_ALL",
        "LANG",
        "TZ",
    }
)


def sandboxed_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Return a minimal environment for a local scanner subprocess.

    Starts from the allowlist inherited from the parent, then merges
    overrides. Use this instead of env=None (which inherits the full
    parent env including any credentials).
    """
    minimal = {k: v for k, v in os.environ.items() if k in MINIMAL_SCANNER_ENV_KEYS}
    if overrides:
        minimal.update(overrides)
    return minimal


def prepare_sandbox_dir(path: Path) -> None:
    """Set 0o750 + POSIX ACL granting `nobody` (the sandbox user) rwx.

    Refuses if `setfacl` is unavailable — silently falling back to 0o777
    would defeat the fix. The `d:u:nflacko:rwx` default ACL ensures files
    created inside by `nobody` are readable by the adapter afterwards.
    """
    if shutil.which("setfacl") is None:
        raise RuntimeError(
            f"setfacl not found; required to grant 'nobody' write access "
            f"to {path} without 0o777. Install: sudo apt install -y acl"
        )
    try:
        os.chmod(path, 0o750)
    except OSError as e:
        raise RuntimeError(f"chmod 0o750 failed on {path}: {e}") from e
    # (v3 hardening) Two changes from the original:
    #   1. "u:nobody:rwx" stays — nobody is the sandbox drop uid.
    #   2. "d:u:nflacko:rwx" was hardcoded to the developer's username.
    #      On any other installation that ACL entry refers to no one and
    #      the adapter cannot read files `nobody` created. Use the
    #      current uid (numeric form works in setfacl).
    import os as _os

    current_uid = _os.getuid()
    result = subprocess.run(
        ["setfacl", "-m", "u:nobody:rwx", "-m", f"d:u:{current_uid}:rwx", str(path)],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError(f"setfacl failed on {path}: {result.stderr.strip()}")


class BinaryDigestError(RuntimeError):
    """On-disk binary does not match the manifest's expected digest."""


@dataclass(frozen=True, slots=True)
class CapturedOutput:
    """Result of run_captured(). Mirrors subprocess.CompletedProcess
    enough for adapter use, plus truncation flags."""

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    truncated_stdout: bool
    truncated_stderr: bool
    isolation_backend: str | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    output_limit_bytes: int = 0


def execution_status_for_capture(
    capture: CapturedOutput,
    *,
    successful_exit_codes: tuple[int, ...] = (0,),
) -> str:
    if capture.timed_out:
        return "TIMED_OUT"
    if capture.returncode not in successful_exit_codes:
        return "FAILED"
    if capture.truncated_stdout or capture.truncated_stderr:
        return "PARTIAL"
    return "COMPLETED"


def ingest_incomplete_capture(
    db,
    *,
    engagements_root: Path,
    engagement_id: str,
    source_name: str,
    actor: str,
    capture: CapturedOutput,
    event_type: str,
    content_bytes: bytes | None = None,
):
    """Persist bounded failure/timeout output without treating it as clean.

    Partial JSON is stored as text because it may not parse. The execution
    status prevents triage/reporting from treating this artifact as complete.
    """
    from sentinel.audit.store import AuditStore
    from sentinel.evidence.ingest import ingest_evidence

    raw = content_bytes
    if raw is None:
        raw = (
            capture.stdout
            + ("\n" if capture.stdout and capture.stderr else "")
            + capture.stderr
        ).encode("utf-8")
    if not raw:
        raw = f"scanner produced no output; exit={capture.returncode}".encode()
    text = raw.decode("utf-8", errors="replace")
    status = execution_status_for_capture(capture)
    evidence = ingest_evidence(
        db,
        engagements_root=engagements_root,
        engagement_id=engagement_id,
        source_name=source_name,
        content_type="text/plain",
        content=text.encode(),
        actor=actor,
        truncated_output=capture.truncated_stdout or capture.truncated_stderr,
        execution_status=status,
        stdout_bytes=max(capture.stdout_bytes, len(capture.stdout.encode("utf-8"))),
        stderr_bytes=max(capture.stderr_bytes, len(capture.stderr.encode("utf-8"))),
        output_limit_bytes=(
            capture.output_limit_bytes
            or DEFAULT_MAX_OUTPUT_BYTES + DEFAULT_MAX_STDERR_BYTES
        ),
        stdout_truncated=capture.truncated_stdout,
        stderr_truncated=capture.truncated_stderr,
        timed_out=capture.timed_out,
        terminated=(capture.returncode < 0),
        process_exit_code=capture.returncode,
    )
    AuditStore(db).append(
        engagement_id=engagement_id,
        actor=actor,
        event_type=event_type,
        decision=status.lower(),
        details={
            "evidence_id": evidence.evidence_id,
            "process_exit_code": capture.returncode,
            "timed_out": capture.timed_out,
            "truncated_stdout": capture.truncated_stdout,
            "truncated_stderr": capture.truncated_stderr,
            "isolation_backend": capture.isolation_backend,
        },
    )
    return evidence


def verify_binary_digest(executable_path: str, expected_sha256: str) -> None:
    """Raise BinaryDigestError if the on-disk binary doesn't match.

    Same contract as sandbox_runner._verify_binary_digest and
    gitleaks._verify_binary_digest: refuse to launch a binary whose
    SHA-256 differs from the manifest. Wrong-version detection is the
    whole point of the manifest.
    """
    p = Path(executable_path)
    if not p.is_file():
        raise BinaryDigestError(f"binary not found: {executable_path}")
    actual = hashlib.sha256(p.read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise BinaryDigestError(
            f"binary digest mismatch for {executable_path}: "
            f"expected {expected_sha256[:16]}..., got {actual[:16]}..."
        )


def run_captured(
    argv: list[str],
    *,
    timeout_seconds: float,
    max_stdout_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> CapturedOutput:
    """Run a subprocess with bounded output and bounded wait.

    Replacement for subprocess.run(capture_output=True, timeout=...).
    On timeout: kills the child, returns timed_out=True, and returns
    whatever output was captured before the kill.

    On output cap: keeps reading to EOF (so the child doesn't block on a
    full pipe), but discards bytes past the cap. truncated_* flags are
    set so the caller can distinguish "tool produced valid output" from
    "tool produced output we truncated."
    """
    if max_stdout_bytes <= 0:
        raise ValueError(f"max_stdout_bytes must be > 0, got {max_stdout_bytes}")
    if max_stderr_bytes <= 0:
        raise ValueError(f"max_stderr_bytes must be > 0, got {max_stderr_bytes}")

    # (batch B) Default to a minimal env allowlist, not the full parent
    # env. Callers may pass an explicit env to override.
    if env is None:
        env = sandboxed_env()
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        cwd=str(cwd) if cwd else None,
        env=env,
        shell=False,
        # (batch B) Own process group so timeout kills the whole tree,
        # not just the immediate child. Scanners that spawn grandchildren
        # (semgrep workers, trivy sub-processes) would otherwise leak.
        start_new_session=True,
    )

    out_buf = bytearray()
    err_buf = bytearray()
    out_trunc = [False]
    err_trunc = [False]

    def _reader(stream, buf, trunc_flag, cap):
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                if len(buf) < cap:
                    remaining = cap - len(buf)
                    buf.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        trunc_flag[0] = True
                else:
                    trunc_flag[0] = True
        except Exception:
            return

    t_out = threading.Thread(
        target=_reader,
        args=(proc.stdout, out_buf, out_trunc, max_stdout_bytes),
        daemon=True,
    )
    t_err = threading.Thread(
        target=_reader,
        args=(proc.stderr, err_buf, err_trunc, max_stderr_bytes),
        daemon=True,
    )
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        # (batch B) Kill the whole process group, not just the child.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    finally:
        t_out.join(timeout=5.0)
        t_err.join(timeout=5.0)

    return CapturedOutput(
        stdout=bytes(out_buf).decode("utf-8", errors="replace"),
        stderr=bytes(err_buf).decode("utf-8", errors="replace"),
        returncode=proc.returncode if proc.returncode is not None else -1,
        timed_out=timed_out,
        truncated_stdout=out_trunc[0],
        truncated_stderr=err_trunc[0],
        stdout_bytes=len(out_buf),
        stderr_bytes=len(err_buf),
        output_limit_bytes=max_stdout_bytes + max_stderr_bytes,
    )


def run_isolated_scanner(
    argv: list[str],
    *,
    input_path: Path,
    timeout_seconds: float,
    extra_readonly: tuple[Path, ...] = (),
    writable_dir: Path | None = None,
    env_overrides: dict[str, str] | None = None,
) -> CapturedOutput:
    """Run a Class 0 scanner on staged read-only inputs with no network.

    Requires bubblewrap with user + network namespaces. There is no unsafe
    fallback: missing namespace support or permissions refuse execution.
    The source is copied without following symlinks into a private staging
    tree, mounted read-only, and the child runs as UID/GID 65534. Only
    explicitly supplied local config/cache paths and an optional output
    directory are mounted in addition to system runtime directories.
    """
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError(
            "Class 0 isolation unavailable: bubblewrap (bwrap) is required; "
            "install it with user/network namespace support"
        )
    source = Path(input_path).resolve(strict=True)
    if not source.is_dir():
        raise RuntimeError(f"scanner input must be a directory: {source}")
    for root, dirs, files in os.walk(source, followlinks=False):
        for name in [*dirs, *files]:
            p = Path(root) / name
            if p.is_symlink():
                raise RuntimeError(f"symlinks are refused in scanner input: {p}")
            if not p.is_dir() and not p.is_file():
                raise RuntimeError(f"special files are refused in scanner input: {p}")

    tmp = Path(tempfile.mkdtemp(prefix="sentinel-class0-"))
    stage = tmp / "input"
    output = Path(writable_dir).resolve() if writable_dir else None
    try:
        # Preserve symlink entries instead of following them while copying;
        # the second walk closes the race with the preflight path check.
        shutil.copytree(source, stage, symlinks=True)
        for root, dirs, files in os.walk(stage, followlinks=False):
            for name in [*dirs, *files]:
                staged_path = Path(root) / name
                if staged_path.is_symlink():
                    raise RuntimeError(
                        f"symlinks are refused in staged scanner input: {staged_path}"
                    )
                if not staged_path.is_dir() and not staged_path.is_file():
                    raise RuntimeError(
                        f"special files are refused in staged scanner input: {staged_path}"
                    )
        for root, dirs, files in os.walk(stage):
            os.chmod(root, 0o555)
            for name in files:
                os.chmod(Path(root) / name, 0o444)
        os.chmod(tmp, 0o711)

        wrapped = [
            bwrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--uid",
            "65534",
            "--gid",
            "65534",
        ]
        for system_path in ("/usr", "/bin", "/sbin", "/lib", "/lib64"):
            if Path(system_path).exists():
                wrapped.extend(["--ro-bind", system_path, system_path])
        for system_file in ("/etc/ld.so.cache", "/etc/passwd", "/etc/group"):
            if Path(system_file).is_file():
                wrapped.extend(["--ro-bind", system_file, system_file])
        wrapped.extend(["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"])
        wrapped.extend(["--ro-bind", str(stage), "/work/input"])

        substitutions = {str(source): "/work/input"}
        for idx, config_path in enumerate(extra_readonly):
            resolved = Path(config_path).resolve(strict=True)
            dest = f"/work/config/{idx}"
            wrapped.extend(["--dir", "/work/config", "--ro-bind", str(resolved), dest])
            substitutions[str(resolved)] = dest
        if output:
            output.mkdir(parents=True, exist_ok=True)
            # Grant only the dedicated scanner account access to this
            # output directory; a missing ACL helper is a hard failure.
            prepare_sandbox_dir(output)
            wrapped.extend(["--bind", str(output), "/work/output"])
            substitutions[str(output)] = "/work/output"
        executable = Path(argv[0]).resolve(strict=True)
        if executable.parent.name == "bin" and executable.parent.parent.name == ".venv":
            venv_root = executable.parent.parent
            wrapped.extend(["--ro-bind", str(venv_root), str(venv_root)])
        if not any(
            str(executable).startswith(p + os.sep)
            for p in ("/usr", "/bin", "/sbin", "/lib", "/lib64")
        ):
            wrapped.extend(["--ro-bind", str(executable), str(executable)])
        translated = []
        for token in argv:
            translated_token = token
            for host, sandbox in substitutions.items():
                if token == host:
                    translated_token = sandbox
                    break
                if token.startswith(host + os.sep):
                    translated_token = sandbox + token[len(host) :]
                    break
                if host in token:
                    translated_token = token.replace(host, sandbox)
                    break
            translated.append(translated_token)
        wrapped.extend(["--", *translated])
        scanner_env = sandboxed_env({"HOME": "/tmp", **(env_overrides or {})})
        for key, value in list(scanner_env.items()):
            for host, sandbox in substitutions.items():
                if value == host or value.startswith(host + os.sep):
                    scanner_env[key] = sandbox + value[len(host) :]
                    break
        capture = run_captured(
            wrapped,
            timeout_seconds=timeout_seconds,
            env=scanner_env,
        )
        return CapturedOutput(
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
            timed_out=capture.timed_out,
            truncated_stdout=capture.truncated_stdout,
            truncated_stderr=capture.truncated_stderr,
            isolation_backend="bubblewrap-unshare-net:uid-65534",
            stdout_bytes=capture.stdout_bytes,
            stderr_bytes=capture.stderr_bytes,
            output_limit_bytes=capture.output_limit_bytes,
        )
    except Exception:
        raise
    finally:
        # Scanner is done before run_captured returns or raises. Restore
        # owner access to remove read-only staged tree, then clean it.
        try:
            for root, dirs, files in os.walk(stage):
                os.chmod(root, 0o700)
                for name in files:
                    os.chmod(Path(root) / name, 0o600)
            shutil.rmtree(tmp, ignore_errors=True)
        except OSError:
            shutil.rmtree(tmp, ignore_errors=True)
