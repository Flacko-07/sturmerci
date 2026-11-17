# SPDX-License-Identifier: Apache-2.0
"""End-to-end Subfinder adapter test (M5.2c).

Uses a fake subfinder binary with deterministic output to prove the
full pipeline: SandboxRunner → namespace → subprocess → parse → candidates.

The real subfinder is registered separately (see operator guide); the
adapter code is identical whether the binary is real or fake — it just
uses whatever the manifest declares.
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
from sentinel.adapters.subfinder import (
    run_subfinder,
    SUBFINDER_VERSION,
    APPROVED_PROVIDERS,
)
from sentinel.engagement.store import EngagementStore
from sentinel.runner import sandbox_runner as _sr
from sentinel.runner.sandbox_runner import SandboxDenied
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="integration requires root (namespace creation)",
)


FAKE_OUTPUT = (
    '{"host":"mail.probe.test","input":"probe.test","source":"crtsh"}\n'
    '{"host":"api.probe.test","input":"probe.test","source":"crtsh"}\n'
    '{"host":"mail.probe.test","input":"probe.test","source":"crtsh"}\n'  # dup
    '{"host":"evil.com","input":"probe.test","source":"crtsh"}\n'  # invalid
)


def _make_fake_subfinder(tmp_path: Path) -> tuple[Path, str]:
    """Create fake subfinder under /tmp (world-traversable for `nobody`).

    Uses chr(10) explicitly for newlines. Verifies the shebang round-trips.
    """
    import tempfile

    bin_dir = Path(tempfile.mkdtemp(prefix="sentinel-test-bin-sf-"))
    bin_dir.chmod(0o755)
    script = bin_dir / "fake_subfinder"
    NL = chr(10)
    content = "#!/bin/sh" + NL + "cat <<'JSON'" + NL + FAKE_OUTPUT + "JSON" + NL
    script.write_text(content)
    script.chmod(0o755)
    # Verify: first two characters MUST be #! and there MUST be a real
    # newline before the first command. If this fails, an escaping layer
    # is corrupting our source.
    first_line = script.read_text().split(NL, 1)[0]
    assert first_line == "#!/bin/sh", (
        f"shebang corrupted in write_text: {first_line!r} (expected '#!/bin/sh')"
    )
    sha = hashlib.sha256(script.read_bytes()).hexdigest()
    return script, sha


def _build_env(tmp_path, *, register_provider=True):
    """Full valid environment for the adapter."""
    binary, binary_sha = _make_fake_subfinder(tmp_path)

    db = Database(tmp_path / "sentinel.sqlite3")
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform="lab",
        program_name="subfinder-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    # Approved target hostname
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

    # Manifest declares crt.sh; adapter will request it
    manifest_store = ManifestStore(db)
    m = ToolManifest(
        tool_name="subfinder",
        version=SUBFINDER_VERSION,
        executable_path=str(binary.resolve()),
        executable_sha256=binary_sha,
        execution_class=2,
        network_access=True,
        allowed_profiles=("subfinder/passive_crtsh",),
        prohibited=("all_sources",),
        limits={"max_runtime_seconds": 60},
        output_format="json",
        infrastructure_endpoints=APPROVED_PROVIDERS,
    )
    registered = manifest_store.register(m, actor="op")

    # Compute current values BEFORE issuing the approval
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
        / "subfinder.py"
    )
    current_scope = _current_scope_lock_hash(db, eng.id, "")
    current_egress = _current_egress_profile_id()
    current_adapter_hash = _current_adapter_code_sha256(adapter_file)

    now = datetime.now(timezone.utc)
    appr = ApprovalRecord(
        approval_id="appr_subfinder_test",
        engagement_id=eng.id,
        engagement_state_at_issue="active",
        policy_snapshot_hash="policy_A",
        scope_lock_hash=current_scope,
        target_asset_ids=target_ids,
        target_asset_ids_hash=target_hash,
        canonical_hostnames=["probe.test"],
        allowed_ports=[443],
        allowed_protocols=["https"],
        allowed_http_methods=["GET"],
        allowed_path_profile="default",
        operation_profile_id="subfinder/passive_crtsh",
        tool_name=m.tool_name,
        tool_version=m.version,
        tool_executable_sha256=binary_sha,
        adapter_code_sha256=current_adapter_hash,
        manifest_hash=registered.manifest_hash,
        egress_profile_id=current_egress,
        normalized_arguments_hash="",
        request_rate_budget=10,
        aggregate_request_budget=100,
        aggregate_byte_budget=1_000_000,
        concurrency_budget=1,
        aggregate_runtime_budget=60,
        aggregate_model_token_budget=10_000,
        issued_by="op",
        issued_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=1)).isoformat(),
        approved_infrastructure_endpoints=(
            list(APPROVED_PROVIDERS) if register_provider else []
        ),
    )
    ApprovalStore(db).issue(appr)

    return {
        "db": db,
        "eng_id": eng.id,
        "approval_id": appr.approval_id,
        "engagements_root": tmp_path / "engagements",
    }


def _stub_resolver(monkeypatch):
    def fake(hostname):
        mapping = {
            "probe.test": ["1.1.1.1"],
            "crt.sh": ["104.21.16.1"],
        }
        return mapping.get(hostname, [])

    monkeypatch.setattr(_sr, "_resolve_hostname", fake)


def test_adapter_happy_path_writes_candidates(tmp_path, monkeypatch):
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path)
    try:
        result = run_subfinder(
            db=env["db"],
            engagement_id=env["eng_id"],
            approval_id=env["approval_id"],
            target_domain="probe.test",
            engagements_root=env["engagements_root"],
            actor="op",
            timeout_seconds=30,
        )
        # 2 unique valid hosts (mail, api); 1 dup; 1 invalid (evil.com)
        assert result.candidates_written == 2
        assert result.candidates_skipped_invalid == 1
        assert result.candidates_skipped_duplicate == 1
        assert result.sandbox.used_providers == APPROVED_PROVIDERS

        # Query only PENDING candidates -- the original probe.test row
        # still exists but has review_state='approved' (promotion updates
        # the state, does not delete the row). We want to verify the
        # adapter's new rows specifically.
        rows = (
            env["db"]
            .connection.execute(
                "SELECT canonical_value, discovery_source FROM candidate_assets "
                "WHERE engagement_id = ? AND review_state = 'pending' "
                "ORDER BY canonical_value",
                (env["eng_id"],),
            )
            .fetchall()
        )
        hosts = [r["canonical_value"] for r in rows]
        assert "api.probe.test" in hosts
        assert "mail.probe.test" in hosts
        assert "evil.com" not in hosts
        assert all(r["discovery_source"] == "subfinder:crtsh" for r in rows)
        # And confirm the original is still there, correctly approved
        original = (
            env["db"]
            .connection.execute(
                "SELECT review_state, discovery_source FROM candidate_assets "
                "WHERE engagement_id = ? AND canonical_value = 'probe.test'",
                (env["eng_id"],),
            )
            .fetchone()
        )
        assert original is not None
        assert original["review_state"] == "approved"
        assert original["discovery_source"] == "test"

        # approved_assets unchanged
        approved = (
            env["db"]
            .connection.execute(
                "SELECT COUNT(*) FROM approved_assets WHERE engagement_id = ?",
                (env["eng_id"],),
            )
            .fetchone()[0]
        )
        assert approved == 1  # still just probe.test
    finally:
        env["db"].close()


def test_adapter_denied_when_provider_not_approved(tmp_path, monkeypatch):
    _stub_resolver(monkeypatch)
    env = _build_env(tmp_path, register_provider=False)
    try:
        with pytest.raises(SandboxDenied, match="not authorized"):
            run_subfinder(
                db=env["db"],
                engagement_id=env["eng_id"],
                approval_id=env["approval_id"],
                target_domain="probe.test",
                engagements_root=env["engagements_root"],
                actor="op",
                timeout_seconds=30,
            )
        # No candidates written
        n = (
            env["db"]
            .connection.execute(
                "SELECT COUNT(*) FROM candidate_assets WHERE engagement_id = ?",
                (env["eng_id"],),
            )
            .fetchone()[0]
        )
        assert n == 1  # only the original probe.test candidate (now approved)
    finally:
        env["db"].close()
