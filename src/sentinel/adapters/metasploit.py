# SPDX-License-Identifier: Apache-2.0
"""metasploit adapter — MSF automation (Class 2 check / Class 3 exploit).

Two profiles, one binary, DB-free:
  metasploit/check    Class 2  auxiliary module `check` only, safe on real targets
  metasploit/exploit  Class 3  gates on intrusive_authorized + lab_environment

Both invoke:
  msfconsole -n -q -r <rc_path>

`-n` disables database. The sandbox cannot reach a postgres socket
(loopback inside the netns is isolated from host loopback), and msf works
DB-free for single-shot runs. DB persistence is not used; sessions are
in-memory and die when msfconsole exits.

Per-run directory layout:
  /tmp/sentinel-msf-<uuid>/
    home/.msf4/
      config                  (empty, msf writes defaults here)
      initial_setup_complete  (marker — suppresses first-run wizard)
      database.yml            (empty — signals "no DB configured")
      logs/ local/ store/ histories/ loot/ plugins/ modules/ data/ bootsnap_cache/
    run.rc                    (generated)
    spool.txt                 (msf writes here; adapter reads it)

All directories 0777 (owned by adapter process uid) so `nobody` (sandbox
user) can write into .msf4/ and spool.txt, and the adapter can rmtree
the whole tree on exit.

Module allowlist (check path): auxiliary/scanner/*, auxiliary/gather/*.
Post-exploitation (exploit/*, post/*) is refused at adapter level with a
dedicated error before SandboxRunner sees the request. The Class 3
profile gate is the second layer.
"""

from __future__ import annotations

import os
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from sentinel.audit.store import AuditStore
from sentinel.approval.store import ApprovalStore
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.runner.profiles import build_argv_for_profile
from sentinel.runner.sandbox_runner import SandboxRequest, run_in_sandbox
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


METASPLOIT_TOOL_NAME = "metasploit"
METASPLOIT_VERSION = "6.5.10-dev"
PROFILE_CHECK = "check"
PROFILE_EXPLOIT = "exploit"

# Modules permitted on the check profile. This is a positive allowlist,
# not a blocklist — anything not matching is refused.
_CHECK_MODULE_RE = re.compile(
    # Auxiliary module paths are 3 or 4 segments:
    #   auxiliary/scanner/http/title                (4)
    #   auxiliary/gather/office365userenum          (3)
    #   auxiliary/scanner/portscan/tcp              (4)
    r"^auxiliary/(scanner|gather)/([a-z0-9_]+/)?[a-z0-9_]+$"
)
# Modules permitted on the exploit profile: exploit/* only. Anything else
# (post/*, payload/*, auxiliary/admin/*) is refused.
_EXPLOIT_MODULE_RE = re.compile(r"^exploit/[a-z0-9_]+/[a-z0-9_]+/[a-z0-9_]+$")

# (batch-2) The reviewed set of auxiliary modules. Extending this list
# requires a security review of the new module's actual behaviour — some
# auxiliary/gather/* modules dump data, run DB enumeration, or query
# third-party APIs. See docs/TECHNICAL_DEBT.md (P0.4 follow-up).
_CHECK_MODULE_ALLOWLIST = frozenset(
    {
        "auxiliary/scanner/http/title",
        "auxiliary/scanner/http/options",
        "auxiliary/scanner/http/http_version",
        "auxiliary/scanner/http/robots_txt",
        "auxiliary/scanner/portscan/tcp",
        "auxiliary/gather/office365userenum",
    }
)

# (batch-2) RC-file injection defenses.
_RC_SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-./:\s,@=]+$")
_RC_SAFE_PAYLOAD_RE = re.compile(r"^[a-z0-9_]+/[a-z0-9_]+/[a-z0-9_]+(?:/[a-z0-9_]+)?$")
_RC_ALLOWED_OPTION_KEYS = frozenset(
    {
        "VHOST",
        "TARGETURI",
        "URI",
        "THREADS",
        "ConnectTimeout",
        "HttpClientTimeout",
    }
)

# Parser anchors. Matches MSF's spool output format:
#   [+] 127.0.0.1:18081 - Title: SimpleHTTP/0.6
#   [-] 127.0.0.1:18081 - The target is not exploitable.
#   [!] 127.0.0.1:18081 - Unknown result.
_RESULT_LINE_RE = re.compile(
    r"^\[([+\-!])\]\s+(\S+:\d+)\s+-\s+(.+?)\s*$",
    re.MULTILINE,
)
_FINDING_RE = re.compile(
    r"^\[\+\]\s+(\S+:\d+)\s+-\s+([^:]+):\s+(.+?)\s*$",
    re.MULTILINE,
)


class MetasploitAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MetasploitFinding:
    host_port: str
    kind: str  # "vulnerable" / "safe" / "unknown" / "info"
    field: str  # for [INFO]/[+] "Field: Value" lines, the field name
    value: str


@dataclass(frozen=True, slots=True)
class MetasploitRunResult:
    findings: list[MetasploitFinding]
    findings_count: int
    evidence: IngestResult
    spool_bytes: int
    process_exit_code: int
    profile: str
    execution_status: str = "COMPLETED"


def _classify_check_msg(msg: str, marker: str) -> str:
    """Classify a check-result line.

    MSF uses [+]/[-]/[!] for "module succeeded/failed/warned", NOT for
    "target is vulnerable/safe/unknown". The actual result lives in the
    message text. Match on message content first, marker as fallback.
    """
    low = msg.lower()
    if "not exploitable" in low or "not vulnerable" in low:
        return "safe"
    if "cannot reliably" in low or "appears to be unknown" in low:
        return "unknown"
    if "vulnerable" in low:
        return "vulnerable"
    return {"+": "vulnerable", "-": "safe", "!": "unknown"}.get(marker, "info")


def parse_spool(text: str) -> list[MetasploitFinding]:
    """Parse msfconsole spool output into findings."""
    if not text:
        return []
    out: list[MetasploitFinding] = []
    # Structured findings: [+] host:port - Field: Value
    for m in _FINDING_RE.finditer(text):
        out.append(
            MetasploitFinding(
                host_port=m.group(1),
                kind="info",
                field=m.group(2).strip(),
                value=m.group(3).strip()[:500],
            )
        )
    # Check-result lines: [+] / [-] / [!] host:port - <message>
    # Skip ones that fit the "Field: Value" shape (already captured above).
    for m in _RESULT_LINE_RE.finditer(text):
        marker, hp, msg = m.group(1), m.group(2), m.group(3)
        if ":" in msg and not msg.startswith("http"):
            continue
        kind = _classify_check_msg(msg, marker)
        out.append(
            MetasploitFinding(
                host_port=hp,
                kind=kind,
                field="check",
                value=msg[:500],
            )
        )
    return out


def _validate_check_module(module: str) -> None:
    if not _CHECK_MODULE_RE.match(module or ""):
        raise MetasploitAdapterError(
            f"module {module!r} not permitted on check profile. "
            f"Allowed: auxiliary/scanner/*, auxiliary/gather/*. "
            f"Use the exploit profile for exploit/*."
        )

    # (batch-2) Per-module allowlist. Well-formed modules are still refused
    # unless they're in the reviewed set.
    if module not in _CHECK_MODULE_ALLOWLIST:
        raise MetasploitAdapterError(
            f"module {module!r} is well-formed but not in the reviewed "
            f"allowlist. Add it to _CHECK_MODULE_ALLOWLIST (in "
            f"src/sentinel/adapters/metasploit.py) after reviewing its "
            f"actual behaviour. Currently allowed: "
            f"{sorted(_CHECK_MODULE_ALLOWLIST)}"
        )


def _validate_exploit_module(module: str) -> None:
    if not _EXPLOIT_MODULE_RE.match(module or ""):
        raise MetasploitAdapterError(
            f"module {module!r} not permitted on exploit profile. "
            f"Allowed: exploit/<platform>/<service>/<name>."
        )


def _validate_rc_value(name: str, value: str) -> None:
    """Reject anything that could inject a new msfconsole command."""
    if not isinstance(value, str):
        raise MetasploitAdapterError(
            f"RC {name} must be str, got {type(value).__name__}"
        )
    if not value:
        raise MetasploitAdapterError(f"RC {name} is empty")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise MetasploitAdapterError(
            f"RC {name} contains newline or NUL — refused to prevent "
            f"command injection into the .rc script"
        )
    if not _RC_SAFE_VALUE_RE.match(value):
        raise MetasploitAdapterError(
            f"RC {name}={value!r} contains characters outside the "
            f"allowlist [A-Za-z0-9 _ - . / : space , @ =]"
        )


def _validate_payload(payload: str) -> None:
    """Reject payload values that don't match platform/arch/type[/name]."""
    if not isinstance(payload, str) or not payload:
        raise MetasploitAdapterError("payload must be a non-empty str")
    if "\n" in payload or "\r" in payload or "\x00" in payload:
        raise MetasploitAdapterError(
            "payload contains newline or NUL — refused to prevent "
            "command injection into the .rc script"
        )
    if not _RC_SAFE_PAYLOAD_RE.match(payload):
        raise MetasploitAdapterError(
            f"payload {payload!r} does not match platform/arch/type[/name] shape"
        )


def _rc_text(
    *,
    module: str,
    hostname: str,
    port: int,
    scheme: str,
    spool_path: Path,
    is_exploit: bool,
    payload: str | None,
    options: dict[str, str],
) -> str:
    """Generate the .rc resource script with full value validation."""
    _validate_rc_value("spool_path", str(spool_path))
    _validate_rc_value("hostname", hostname)
    if not (1 <= int(port) <= 65535):
        raise MetasploitAdapterError(f"port out of range: {port!r}")
    if scheme not in ("http", "https"):
        raise MetasploitAdapterError(f"scheme must be http or https: {scheme!r}")

    for k, v in options.items():
        if k not in _RC_ALLOWED_OPTION_KEYS:
            raise MetasploitAdapterError(
                f"option {k!r} not in allowed RC option keys "
                f"({sorted(_RC_ALLOWED_OPTION_KEYS)})"
            )
        _validate_rc_value(f"option {k}", v)

    if is_exploit and payload:
        _validate_payload(payload)

    lines = [
        f"spool {spool_path}",
        f"use {module}",
        f"set RHOSTS {hostname}",
        f"set RPORT {port}",
        "set SSL true" if scheme == "https" else "set SSL false",
    ]
    for k, v in options.items():
        lines.append(f"set {k} {v}")
    lines.append("set THREADS 1")
    if is_exploit:
        if payload:
            lines.append(f"set PAYLOAD {payload}")
        lines.append("exploit -z")
        lines.append("sleep 5")
        lines.append("sessions -K")
    else:
        lines.append("check")
        lines.append("run")
    lines.extend(["spool off", "exit"])
    return "\n".join(lines) + "\n"


def _prepare_run_dir() -> tuple[Path, Path, Path, Path]:
    """Create per-run directory tree with restricted permissions.

    (batch-2) Directories: 0o750 + POSIX ACL granting `nobody` rwx.
    Refuses if `setfacl` is unavailable — silently falling back to 0o777
    would defeat the fix.
    """
    import shutil as _sh
    import subprocess as _sp

    if _sh.which("setfacl") is None:
        raise MetasploitAdapterError(
            "setfacl not found on PATH. Metasploit's per-run directory "
            "requires POSIX ACLs to grant the sandbox user `nobody` "
            "write access without 0777. Install with: "
            "sudo apt install -y acl"
        )

    run_id = uuid.uuid4().hex[:16]
    run_dir = Path(f"/tmp/sentinel-msf-{run_id}")
    home_dir = run_dir / "home"
    msf4 = home_dir / ".msf4"
    spool = run_dir / "spool.txt"

    msf4.mkdir(parents=True, exist_ok=True)
    (msf4 / "config").write_text("", encoding="utf-8")
    (msf4 / "initial_setup_complete").write_text("", encoding="utf-8")
    (msf4 / "database.yml").write_text("", encoding="utf-8")
    for d in (
        "logs",
        "local",
        "store",
        "histories",
        "loot",
        "plugins",
        "modules",
        "data",
        "bootsnap_cache",
    ):
        (msf4 / d).mkdir(exist_ok=True)

    all_dirs = [run_dir, home_dir, msf4, *msf4.rglob("*")]
    for d in all_dirs:
        if not d.is_dir():
            continue
        try:
            os.chmod(d, 0o750)
        except OSError as e:
            raise MetasploitAdapterError(f"chmod 0o750 failed on {d}: {e}") from e
        result = _sp.run(
            ["setfacl", "-m", "u:nobody:rwx", "-m", f"d:u:{os.getuid()}:rwx", str(d)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            raise MetasploitAdapterError(
                f"setfacl failed on {d}: {result.stderr.strip()}. "
                "Refusing to fall back to 0777. Install `acl` "
                "(sudo apt install -y acl) or check filesystem ACL "
                "support."
            )

    for f in (msf4 / "config", msf4 / "initial_setup_complete", msf4 / "database.yml"):
        try:
            os.chmod(f, 0o640)
        except OSError:
            pass

    return run_dir, home_dir, msf4, spool


def _run(
    *,
    db,
    engagement_id,
    approval_id,
    target_hostname,
    port,
    scheme,
    engagements_root,
    module,
    is_exploit,
    payload,
    options,
    actor,
    timeout_seconds,
) -> MetasploitRunResult:
    db_obj, owns = coerce_db(db)
    run_dir: Path | None = None
    try:
        approval = ApprovalStore(db_obj).get(approval_id)
        if approval is None:
            raise MetasploitAdapterError(f"approval {approval_id!r} not found")
        if approval.revoked_at_utc:
            raise MetasploitAdapterError(f"approval {approval_id!r} revoked")

        # Module allowlist check happens at adapter level FIRST — before
        # SandboxRunner sees the request — so a disallowed module fails
        # fast with a clear error rather than a generic sandbox_denied.
        if is_exploit:
            _validate_exploit_module(module)
        else:
            _validate_check_module(module)

        manifest = ManifestStore(db_obj).get_by_tool_version(
            METASPLOIT_TOOL_NAME,
            METASPLOIT_VERSION,
        )
        if manifest is None:
            raise MetasploitAdapterError(
                f"no manifest for {METASPLOIT_TOOL_NAME} "
                f"{METASPLOIT_VERSION} — register first"
            )
        if not manifest.manifest.network_access:
            raise MetasploitAdapterError(
                "metasploit manifest must be network_access=True"
            )

        run_dir, home_dir, msf4, spool = _prepare_run_dir()
        rc_path = run_dir / "run.rc"
        rc_path.write_text(
            _rc_text(
                module=module,
                hostname=target_hostname,
                port=port,
                scheme=scheme,
                spool_path=spool,
                is_exploit=is_exploit,
                payload=payload,
                options=options,
            ),
            encoding="utf-8",
        )
        os.chmod(rc_path, 0o644)

        profile_name = "metasploit/exploit" if is_exploit else "metasploit/check"
        params = {
            "module": module,
            "hostname": target_hostname,
            "port": port,
            "scheme": scheme,
            "rc_path": str(rc_path),
        }
        argv = build_argv_for_profile(
            profile_name=profile_name,
            executable_path=manifest.manifest.executable_path,
            params=params,
        )

        request = SandboxRequest(
            hostname=target_hostname,
            port=port,
            protocol=scheme,
            method="GET",
            path="/",
            argv=argv,
            timeout_seconds=timeout_seconds,
            additional_ports=(),
            provider_endpoints=(),
            requires_target_connection=True,
            estimated_requests=20,
            operation_profile=profile_name,
            profile_params=params,
            env_overrides={"HOME": str(home_dir)},
            cwd=str(run_dir),
        )

        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=METASPLOIT_TOOL_NAME,
            adapter_version=METASPLOIT_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        spool_text = (
            spool.read_text(encoding="utf-8", errors="replace")
            if spool.is_file()
            else ""
        )
        findings = parse_spool(spool_text)

        evidence = ingest_evidence(
            db_obj,
            engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"metasploit_{module.replace('/', '_')}_{target_hostname}_{port}.txt",
            content_type="text/plain",
            content=(spool_text or "[no spool produced]").encode("utf-8"),
            actor=actor,
            truncated_output=result.truncated_stdout or result.truncated_stderr,
            execution_status=result.execution_status,
            stdout_bytes=result.stdout_bytes,
            stderr_bytes=result.stderr_bytes,
            output_limit_bytes=result.output_limit_bytes,
            stdout_truncated=result.truncated_stdout,
            stderr_truncated=result.truncated_stderr,
            timed_out=result.timed_out,
            terminated=result.terminated,
            process_exit_code=result.exit_code,
        )

        AuditStore(db_obj).append(
            engagement_id=engagement_id,
            actor=actor,
            event_type="metasploit_run",
            decision="ok" if result.exit_code == 0 else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "profile": profile_name,
                "module": module,
                "target": f"{target_hostname}:{port}",
                "findings_count": len(findings),
                "evidence_id": evidence.evidence_id,
                "exit_code": result.exit_code,
            },
        )

        return MetasploitRunResult(
            findings=findings,
            findings_count=len(findings),
            evidence=evidence,
            spool_bytes=len(spool_text.encode("utf-8")),
            process_exit_code=result.exit_code,
            profile=profile_name,
            execution_status=result.execution_status,
        )
    finally:
        if run_dir is not None:
            shutil.rmtree(run_dir, ignore_errors=True)
        if owns:
            db_obj.close()


def run_metasploit_check(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_hostname: str,
    port: int,
    scheme: str,
    module: str,
    engagements_root: Path,
    options: dict[str, str] | None = None,
    actor: str = "operator",
    timeout_seconds: int = 300,
) -> MetasploitRunResult:
    """Run msfconsole check on an auxiliary module (Class 2, DB-free)."""
    return _run(
        db=db,
        engagement_id=engagement_id,
        approval_id=approval_id,
        target_hostname=target_hostname,
        port=port,
        scheme=scheme,
        engagements_root=engagements_root,
        module=module,
        is_exploit=False,
        payload=None,
        options=dict(options or {}),
        actor=actor,
        timeout_seconds=timeout_seconds,
    )


def run_metasploit_exploit(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_hostname: str,
    port: int,
    scheme: str,
    module: str,
    engagements_root: Path,
    payload: str | None = None,
    options: dict[str, str] | None = None,
    actor: str = "operator",
    timeout_seconds: int = 600,
) -> MetasploitRunResult:
    """Run msfconsole exploit on an exploit module (Class 3, LAB-ONLY)."""
    return _run(
        db=db,
        engagement_id=engagement_id,
        approval_id=approval_id,
        target_hostname=target_hostname,
        port=port,
        scheme=scheme,
        engagements_root=engagements_root,
        module=module,
        is_exploit=True,
        payload=payload,
        options=dict(options or {}),
        actor=actor,
        timeout_seconds=timeout_seconds,
    )
