# SPDX-License-Identifier: Apache-2.0
"""metasploit adapter tests — hermetic, mocks run_in_sandbox."""

from __future__ import annotations

import hashlib
import shutil
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import sentinel.runner.builtin_profiles  # noqa: F401
from sentinel.adapters.metasploit import (
    run_metasploit_check,
    parse_spool,
    MetasploitAdapterError,
    _validate_check_module,
    _validate_exploit_module,
    _rc_text,
)
from sentinel.approval.store import (
    ApprovalRecord,
    ApprovalStore,
    target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.profiles import build_argv_for_profile, get_profile
from sentinel.runner.sandbox_runner import SandboxResult
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


import subprocess as _sp
import shutil as _sh


@pytest.fixture(autouse=True)
def _fake_setfacl(monkeypatch):
    """Stub setfacl so hermetic tests don't require the `acl` package.

    The real _prepare_run_dir refuses if setfacl is unavailable. Hermetic
    tests exercise everything *except* the actual ACL application.
    """
    orig_run = _sp.run
    orig_which = _sh.which

    def fake_run(cmd, *args, **kwargs):
        if isinstance(cmd, list) and cmd and cmd[0] == "setfacl":
            return _sp.CompletedProcess(cmd, 0, "", "")
        return orig_run(cmd, *args, **kwargs)

    def fake_which(name):
        if name == "setfacl":
            return "/usr/bin/setfacl"
        return orig_which(name)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("shutil.which", fake_which)


SPOOL_TITLE = """\
[*] Auxiliary module execution completed
[+] 127.0.0.1:18081 - Title: SimpleHTTP/0.6 Python/3.12.3
[*] Scanned 1 of 1 hosts (100% complete)
"""

SPOOL_CHECK_SAFE = """\
[+] 127.0.0.1:18081 - The target is not exploitable.
[*] Auxiliary module execution completed
"""

SPOOL_CHECK_VULN = """\
[+] 127.0.0.1:18081 - The target is vulnerable.
[*] Auxiliary module execution completed
"""


def test_parse_spool_title_finding():
    findings = parse_spool(SPOOL_TITLE)
    assert any(f.field == "Title" and "SimpleHTTP" in f.value for f in findings)


def test_parse_spool_check_safe():
    findings = parse_spool(SPOOL_CHECK_SAFE)
    assert any(f.kind == "safe" for f in findings)


def test_parse_spool_check_vulnerable():
    findings = parse_spool(SPOOL_CHECK_VULN)
    assert any(f.kind == "vulnerable" for f in findings)


def test_parse_spool_empty():
    assert parse_spool("") == []


def test_check_module_allowlist_accepts_scanner():
    _validate_check_module("auxiliary/scanner/http/title")
    _validate_check_module("auxiliary/gather/office365userenum")


def test_check_module_allowlist_rejects_exploit():
    with pytest.raises(MetasploitAdapterError, match="not permitted"):
        _validate_check_module("exploit/windows/smb/ms17_010_eternalblue")


def test_exploit_module_allowlist_rejects_auxiliary():
    with pytest.raises(MetasploitAdapterError, match="not permitted"):
        _validate_exploit_module("auxiliary/scanner/http/title")


def test_exploit_module_allowlist_accepts_exploit():
    _validate_exploit_module("exploit/windows/smb/ms17_010_eternalblue")


def test_profile_check_is_class2():
    assert get_profile("metasploit/check").execution_class == 2


def test_profile_exploit_is_class3():
    assert get_profile("metasploit/exploit").execution_class == 3


def test_check_profile_builds_argv():
    argv = build_argv_for_profile(
        profile_name="metasploit/check",
        executable_path="/opt/metasploit-framework/bin/msfconsole",
        params={
            "module": "auxiliary/scanner/http/title",
            "hostname": "127.0.0.1",
            "port": 18080,
            "scheme": "http",
            "rc_path": "/tmp/sentinel-msf-abc123/run.rc",
        },
    )
    assert argv[0] == "/opt/metasploit-framework/bin/msfconsole"
    assert "-n" in argv  # DB-free
    assert "-q" in argv
    assert "-r" in argv


def test_profile_refuses_rc_outside_tmp():
    with pytest.raises(Exception, match="rc_path"):
        build_argv_for_profile(
            profile_name="metasploit/check",
            executable_path="/opt/metasploit-framework/bin/msfconsole",
            params={
                "module": "auxiliary/scanner/http/title",
                "hostname": "127.0.0.1",
                "port": 18080,
                "scheme": "http",
                "rc_path": "/etc/passwd",
            },
        )


def test_rc_text_check_has_no_sessions_kill():
    text = _rc_text(
        module="auxiliary/scanner/http/title",
        hostname="127.0.0.1",
        port=18080,
        scheme="http",
        spool_path=Path("/tmp/spool.txt"),
        is_exploit=False,
        payload=None,
        options={},
    )
    assert "spool /tmp/spool.txt" in text
    assert "use auxiliary/scanner/http/title" in text
    assert "set RHOSTS 127.0.0.1" in text
    assert "set RPORT 18080" in text
    assert "set SSL false" in text
    assert "check" in text
    assert "run" in text
    assert "sessions -K" not in text  # check profile doesn't kill sessions


def test_rc_text_exploit_kills_sessions():
    text = _rc_text(
        module="exploit/windows/smb/ms17_010_eternalblue",
        hostname="127.0.0.1",
        port=445,
        scheme="http",
        spool_path=Path("/tmp/spool.txt"),
        is_exploit=True,
        payload="windows/x64/meterpreter/reverse_tcp",
        options={},
    )
    assert "set PAYLOAD windows/x64/meterpreter/reverse_tcp" in text
    assert "exploit -z" in text
    assert "sessions -K" in text


def test_rc_text_https_sets_ssl_true():
    text = _rc_text(
        module="auxiliary/scanner/http/title",
        hostname="127.0.0.1",
        port=443,
        scheme="https",
        spool_path=Path("/tmp/spool.txt"),
        is_exploit=False,
        payload=None,
        options={},
    )
    assert "set SSL true" in text


def _build_env(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="msf-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id,
        raw_value="127.0.0.1",
        canonical_value="127.0.0.1",
        asset_type="ip",
        discovery_source="t",
    )
    aid = astore.promote_candidate(cid, approved_by="op")

    fake_binary = "/bin/true"
    h = hashlib.sha256(Path(fake_binary).read_bytes()).hexdigest()
    from sentinel.adapters.metasploit import METASPLOIT_VERSION

    ManifestStore(db).register(
        ToolManifest(
            tool_name="metasploit",
            version=METASPLOIT_VERSION,
            executable_path=fake_binary,
            executable_sha256=h,
            execution_class=2,
            network_access=True,
            allowed_profiles=("check", "exploit"),
            prohibited=("-x", "-e"),
            limits={"max_runtime_seconds": 600, "max_output_megabytes": 10},
            output_format="text",
        ),
        actor="test",
    )

    from sentinel.runner.sandbox_runner import (
        _current_scope_lock_hash,
        _current_egress_profile_id,
        _current_adapter_code_sha256,
    )

    adapter_path = Path("src/sentinel/adapters/metasploit.py")
    now = datetime.now(timezone.utc)

    def _make(approval_id, *, intrusive=False, lab=False):
        appr = ApprovalRecord(
            approval_id=approval_id,
            engagement_id=eng.id,
            engagement_state_at_issue="active",
            policy_snapshot_hash="p",
            scope_lock_hash=_current_scope_lock_hash(db, eng.id, ""),
            target_asset_ids=[aid],
            target_asset_ids_hash=target_asset_ids_hash([aid]),
            canonical_hostnames=["127.0.0.1"],
            allowed_ports=[18080],
            allowed_protocols=["http"],
            allowed_http_methods=["GET"],
            allowed_path_profile="default",
            operation_profile_id="check",
            tool_name="metasploit",
            tool_version=METASPLOIT_VERSION,
            tool_executable_sha256=h,
            adapter_code_sha256=_current_adapter_code_sha256(adapter_path),
            manifest_hash=ManifestStore(db)
            .get_by_tool_version("metasploit", METASPLOIT_VERSION)
            .manifest_hash,
            egress_profile_id=_current_egress_profile_id(),
            normalized_arguments_hash="",
            request_rate_budget=5,
            aggregate_request_budget=100,
            aggregate_byte_budget=10_000_000,
            concurrency_budget=1,
            aggregate_runtime_budget=600,
            aggregate_model_token_budget=0,
            issued_by="op",
            issued_at_utc=now.isoformat(),
            expires_at_utc=(now + timedelta(hours=1)).isoformat(),
            intrusive_authorized=intrusive,
            lab_environment=lab,
        )
        ApprovalStore(db).issue(appr)
        return appr.approval_id

    return {
        "db": db,
        "eng_id": eng.id,
        "approval_check": _make("appr_msf_check"),
        "approval_exploit_nogate": _make("appr_msf_exploit_nogate"),
        "approval_exploit_ok": _make("appr_msf_exploit_ok", intrusive=True, lab=True),
        "engagements_root": tmp_path / "engagements",
    }


def test_run_metasploit_check_happy(tmp_path):
    env = _build_env(tmp_path)
    fake = SandboxResult(
        stdout="",
        stderr="",
        exit_code=0,
        duration_seconds=1.0,
        namespace_name="ns",
        resolved_ip="127.0.0.1",
        audit_event_seq=1,
        used_providers=(),
        resolved_ips=("127.0.0.1",),
    )
    fixed = "testfixed1234567"
    # Pre-create the spool the adapter will read
    run_dir = Path(f"/tmp/sentinel-msf-{fixed}")
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "spool.txt").write_text(SPOOL_TITLE)
    try:
        with patch("sentinel.adapters.metasploit.run_in_sandbox", return_value=fake):
            with patch.object(
                _uuid, "uuid4", return_value=type("U", (), {"hex": fixed})
            ):
                result = run_metasploit_check(
                    db=env["db"],
                    engagement_id=env["eng_id"],
                    approval_id=env["approval_check"],
                    target_hostname="127.0.0.1",
                    port=18080,
                    scheme="http",
                    module="auxiliary/scanner/http/title",
                    engagements_root=env["engagements_root"],
                )
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
    assert result.profile == "metasploit/check"
    assert result.findings_count >= 1
    assert result.evidence.evidence_id.startswith("ev_")
    env["db"].close()


def test_check_rejects_exploit_module(tmp_path):
    env = _build_env(tmp_path)
    with pytest.raises(MetasploitAdapterError, match="not permitted"):
        run_metasploit_check(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_check"],
            target_hostname="127.0.0.1",
            port=18080,
            scheme="http",
            module="exploit/windows/smb/ms17_010_eternalblue",
            engagements_root=env["engagements_root"],
        )
    env["db"].close()


# ====================================================================
# batch-2: RC injection defenses
# ====================================================================


def test_rc_text_rejects_newline_in_options():
    with pytest.raises(MetasploitAdapterError, match="newline"):
        _rc_text(
            module="auxiliary/scanner/http/title",
            hostname="127.0.0.1",
            port=18080,
            scheme="http",
            spool_path=Path("/tmp/spool.txt"),
            is_exploit=False,
            payload=None,
            options={"VHOST": "good.example\nset PAYLOAD evil"},
        )


def test_rc_text_rejects_newline_in_option_value_cr():
    with pytest.raises(MetasploitAdapterError, match="newline"):
        _rc_text(
            module="auxiliary/scanner/http/title",
            hostname="127.0.0.1",
            port=18080,
            scheme="http",
            spool_path=Path("/tmp/spool.txt"),
            is_exploit=False,
            payload=None,
            options={"VHOST": "good\rset EXPLOIT"},
        )


def test_rc_text_rejects_newline_in_payload():
    with pytest.raises(MetasploitAdapterError, match="newline"):
        _rc_text(
            module="exploit/windows/smb/ms17_010_eternalblue",
            hostname="127.0.0.1",
            port=445,
            scheme="http",
            spool_path=Path("/tmp/spool.txt"),
            is_exploit=True,
            payload="windows/x64/meterpreter/reverse_tcp\nsessions -K",
            options={},
        )


def test_rc_text_rejects_shell_metacharacters_in_options():
    for bad in (
        "bad; set PAYLOAD evil",
        "bad`whoami`",
        "bad$(cmd)",
        "bad|pipe",
        "bad&bg",
        'bad"quote"',
    ):
        with pytest.raises(MetasploitAdapterError, match="outside"):
            _rc_text(
                module="auxiliary/scanner/http/title",
                hostname="127.0.0.1",
                port=18080,
                scheme="http",
                spool_path=Path("/tmp/spool.txt"),
                is_exploit=False,
                payload=None,
                options={"VHOST": bad},
            )


def test_rc_text_rejects_option_key_not_in_allowlist():
    with pytest.raises(MetasploitAdapterError, match="not in allowed"):
        _rc_text(
            module="auxiliary/scanner/http/title",
            hostname="127.0.0.1",
            port=18080,
            scheme="http",
            spool_path=Path("/tmp/spool.txt"),
            is_exploit=False,
            payload=None,
            options={"PAYLOAD": "cmd/unix/generic"},
        )


def test_rc_text_rejects_malformed_payload():
    with pytest.raises(MetasploitAdapterError, match="does not match"):
        _rc_text(
            module="exploit/windows/smb/ms17_010_eternalblue",
            hostname="127.0.0.1",
            port=445,
            scheme="http",
            spool_path=Path("/tmp/spool.txt"),
            is_exploit=True,
            payload="malformed-payload",
            options={},
        )


def test_rc_text_rejects_newline_in_hostname():
    with pytest.raises(MetasploitAdapterError, match="newline"):
        _rc_text(
            module="auxiliary/scanner/http/title",
            hostname="127.0.0.1\nset PAYLOAD evil",
            port=18080,
            scheme="http",
            spool_path=Path("/tmp/spool.txt"),
            is_exploit=False,
            payload=None,
            options={},
        )


def test_check_module_allowlist_refuses_unreviewed():
    with pytest.raises(MetasploitAdapterError, match="reviewed"):
        _validate_check_module("auxiliary/gather/ike_version")


def test_prepare_run_dir_refuses_when_setfacl_missing(monkeypatch):
    from sentinel.adapters import metasploit as msf_mod

    monkeypatch.setattr("shutil.which", lambda n: None)
    with pytest.raises(MetasploitAdapterError, match="setfacl not found"):
        msf_mod._prepare_run_dir()


def test_prepare_run_dir_refuses_when_setfacl_fails(monkeypatch):
    import subprocess as _sp
    from sentinel.adapters import metasploit as msf_mod

    def fake_run(cmd, *a, **kw):
        if isinstance(cmd, list) and cmd and cmd[0] == "setfacl":
            return _sp.CompletedProcess(cmd, 1, "", "operation not supported")
        return _sp.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("subprocess.run", fake_run)
    with pytest.raises(MetasploitAdapterError, match="setfacl failed"):
        msf_mod._prepare_run_dir()
