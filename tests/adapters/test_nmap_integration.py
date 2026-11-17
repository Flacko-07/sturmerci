# SPDX-License-Identifier: Apache-2.0
"""End-to-end Nmap adapter test (M6.1).

Uses a fake nmap binary that emits deterministic XML. Proves the full
stack: SandboxRunner → namespace → subprocess → parse → candidate_assets.
Real Nmap is registered separately per the operator guide.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.approval.store import (
    ApprovalRecord,
    ApprovalStore,
    target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.adapters.nmap import run_nmap, NMAP_VERSION
from sentinel.engagement.store import EngagementStore
from sentinel.runner import sandbox_runner as _sr
from sentinel.runner.sandbox_runner import SandboxDenied
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="integration requires root (namespace creation)",
)


FAKE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.1.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
      <port protocol="tcp" portid="80"><state state="open"/></port>
      <port protocol="tcp" portid="443"><state state="open"/></port>
      <port protocol="tcp" portid="8080"><state state="closed"/></port>
    </ports>
  </host>
  <runstats>
    <finished exit="success" time="1500"/>
  </runstats>
</nmaprun>"""


def _make_fake_nmap(tmp_path: Path) -> tuple[Path, str]:
    """Create fake nmap under /tmp (world-traversable for `nobody`)."""
    import tempfile

    bin_dir = Path(tempfile.mkdtemp(prefix="sentinel-test-bin-nm-"))
    bin_dir.chmod(0o755)
    script = bin_dir / "fake_nmap"
    NL = chr(10)
    content = "#!/bin/sh" + NL + "cat <<'XML'" + NL + FAKE_XML + NL + "XML" + NL
    script.write_text(content)
    script.chmod(0o755)
    first_line = script.read_text().split(NL, 1)[0]
    assert first_line == "#!/bin/sh", f"shebang corrupted in write_text: {first_line!r}"
    sha = hashlib.sha256(script.read_bytes()).hexdigest()
    return script, sha


def _build_env(tmp_path, *, approved_ports):
    binary, binary_sha = _make_fake_nmap(tmp_path)
    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name="nmap-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    asset_store = AssetStore(db)
    cid = asset_store.add_candidate(
        engagement_id=eng.id,
        raw_value="probe.test",
        canonical_value="probe.test",
        asset_type="hostname",
        discovery_source="test",
    )
    asset_id = asset_store.promote_candidate(cid, approved_by="op")
    target_ids = [asset_id]
    target_hash = target_asset_ids_hash(target_ids)

    manifest_store = ManifestStore(db)
    m = ToolManifest(
        tool_name="nmap",
        version=NMAP_VERSION,
        executable_path=str(binary.resolve()),
        executable_sha256=binary_sha,
        execution_class=2,
        network_access=True,
        allowed_profiles=("nmap/tcp_connect_scan",),
        prohibited=(
            "nse_scripts",
            "os_detection",
            "service_version_detection",
            "udp_scan",
            "raw_syn_scan",
        ),
        limits={"max_runtime_seconds": 300},
        output_format="xml",
        infrastructure_endpoints=(),
    )
    registered = manifest_store.register(m, actor="op")

    from sentinel.runner.sandbox_runner import (
        _current_scope_lock_hash,
        _current_egress_profile_id,
        _current_adapter_code_sha256,
    )

    adapter_file = (
        Path(__file__).parent.parent.parent
        / "src"
        / "sentinel"
        / "adapters"
        / "nmap.py"
    )
    current_scope = _current_scope_lock_hash(db, eng.id, "")
    current_egress = _current_egress_profile_id()
    current_adapter_hash = _current_adapter_code_sha256(adapter_file)

    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_nmap_test",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="policy_A",
        scope_lock_hash=current_scope,
        target_asset_ids=target_ids,
        target_asset_ids_hash=target_hash,
        canonical_hostnames=["probe.test"],
        allowed_ports=approved_ports,
        allowed_protocols=["tcp"],
        allowed_http_methods=["connect"],
        allowed_path_profile="default",
        operation_profile_id="nmap/tcp_connect_scan",
        tool_name=m.tool_name,
        tool_version=m.version,
        tool_executable_sha256=binary_sha,
        adapter_code_sha256=current_adapter_hash,
        manifest_hash=registered.manifest_hash,
        egress_profile_id=current_egress,
        normalized_arguments_hash="",
        request_rate_budget=20,
        aggregate_request_budget=100,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=300,
        aggregate_model_token_budget=10_000,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
        approved_infrastructure_endpoints=[],
        port_scanning_authorized=True,  # operator affirmed program permits
    )
    ApprovalStore(db).issue(appr)

    return {
        "db": db,
        "eng_id": eng.id,
        "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
    }


def _stub_resolver(monkeypatch):
    monkeypatch.setattr(
        _sr,
        "_resolve_hostname",
        lambda h: ["1.1.1.1"] if h == "probe.test" else [],
    )


def test_happy_path_writes_open_ports_as_services(tmp_path, monkeypatch):
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, approved_ports=[22, 80, 443, 8080])
    try:
        result = run_nmap(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_hostname="probe.test",
            ports=[22, 80, 443, 8080],
            engagements_root=env["engagements_root"],
            actor="op",
            timeout_seconds=30,
        )
        # 3 open, 1 closed — only open becomes candidates
        assert result.open_ports_written == 3
        rows = (
            env["db"]
            .connection.execute(
                "SELECT canonical_value, asset_type, discovery_source "
                "FROM candidate_assets "
                "WHERE engagement_id = ? AND review_state = 'pending' "
                "ORDER BY canonical_value",
                (env["eng_id"],),
            )
            .fetchall()
        )
        values = [r["canonical_value"] for r in rows]
        assert "probe.test:22/tcp" in values
        assert "probe.test:80/tcp" in values
        assert "probe.test:443/tcp" in values
        assert "probe.test:8080/tcp" not in values  # closed
        assert all(r["asset_type"] == "service" for r in rows)
        assert all(r["discovery_source"] == "nmap:tcp_connect_scan" for r in rows)
    finally:
        env["db"].close()


def test_unapproved_port_denied(tmp_path, monkeypatch):
    """Approval covers only 22,80,443; adapter asks for 3306 too -> denied."""
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, approved_ports=[22, 80, 443])
    try:
        with pytest.raises(SandboxDenied, match="port 3306"):
            run_nmap(
                db=env["db"],
                engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                target_hostname="probe.test",
                ports=[22, 80, 443, 3306],
                engagements_root=env["engagements_root"],
                actor="op",
                timeout_seconds=30,
            )
        # Nothing was written
        n = (
            env["db"]
            .connection.execute(
                "SELECT COUNT(*) FROM candidate_assets "
                "WHERE engagement_id = ? AND asset_type = 'service'",
                (env["eng_id"],),
            )
            .fetchone()[0]
        )
        assert n == 0
    finally:
        env["db"].close()


def test_refused_when_port_scanning_not_authorized(tmp_path, monkeypatch):
    """P0.5: no port_scanning_authorized -> Nmap refuses before sandbox.

    Approving a hostname does not authorize scanning the shared
    infrastructure it resolves to. Operator must affirm explicitly.
    """
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, approved_ports=[22, 80, 443, 8080])
    # Flip the flag back to False to simulate the un-affirmed state
    with env["db"].transaction() as conn:
        conn.execute(
            "UPDATE approvals SET port_scanning_authorized = 0 WHERE approval_id = ?",
            (env["approval_id"],),
        )
    try:
        with pytest.raises(SandboxDenied, match="does not authorize port scanning"):
            run_nmap(
                db=env["db"],
                engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                target_hostname="probe.test",
                ports=[22, 80, 443, 8080],
                engagements_root=env["engagements_root"],
                actor="op",
                timeout_seconds=30,
            )
        # No candidates written
        n = (
            env["db"]
            .connection.execute(
                "SELECT COUNT(*) FROM candidate_assets "
                "WHERE engagement_id = ? AND asset_type = 'service'",
                (env["eng_id"],),
            )
            .fetchone()[0]
        )
        assert n == 0
    finally:
        env["db"].close()
