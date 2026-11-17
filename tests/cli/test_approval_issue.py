# SPDX-License-Identifier: Apache-2.0
"""approval issue CLI — P0.2 explicit authorization tests.

Verifies:
- Ports/methods/protocols are never auto-derived from the manifest
- Providers are never auto-populated from the manifest
- Network tools require --port and --protocol
- --intrusive requires --yes in automation
- --lab requires engagement.platform='lab'
- --profile must be in manifest.allowed_profiles
- --policy-snapshot must match a policy_snapshots row
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel.assets.store import AssetStore
from sentinel.cli import app
from sentinel.engagement.store import EngagementStore
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


runner = CliRunner()


def _setup(tmp_path, monkeypatch, *, network=True,
           allowed_profiles=("scan",), providers=(),
           platform="lab"):
    """Build an isolated DB + manifest + active engagement + asset."""
    db_path = tmp_path / "sentinel.sqlite3"
    monkeypatch.setenv("SENTINEL_DB_PATH", str(db_path))
    # Patch the CLI database factory to keep this test isolated from the
    # process-wide default data directory.
    import sentinel.cli as cli_mod
    if hasattr(cli_mod, "_db"):
        monkeypatch.setattr(cli_mod, "_db", lambda: Database(db_path))

    db = Database(db_path)
    eng_store = EngagementStore(db)
    eng = eng_store.create(
        platform=platform, program_name="cli-test", policy_url=None,
        actor="op", engagements_root=tmp_path / "engagements",
    )
    eng_store.transition(eng.id, "scope_review", "op")
    eng_store.transition(eng.id, "active", "op")

    astore = AssetStore(db)
    cid = astore.add_candidate(
        engagement_id=eng.id, raw_value="127.0.0.1",
        canonical_value="127.0.0.1", asset_type="ip",
        discovery_source="t",
    )
    astore.promote_candidate(cid, approved_by="op")

    fake_binary = "/bin/true"
    h = hashlib.sha256(Path(fake_binary).read_bytes()).hexdigest()
    ManifestStore(db).register(ToolManifest(
        tool_name="fake", version="1.0",
        executable_path=fake_binary, executable_sha256=h,
        execution_class=3 if network else 0,
        network_access=network,
        allowed_profiles=tuple(allowed_profiles),
        prohibited=(), limits={"max_runtime_seconds": 60},
        output_format="text",
        infrastructure_endpoints=tuple(providers),
    ), actor="test")
    db.close()
    return eng.id


def _invoke(eng_id, *extra):
    return runner.invoke(app, [
        "approval", "issue", eng_id,
        "--tool", "fake", "--version", "1.0",
        "--actor", "op",
        *extra,
    ])


def test_network_tool_requires_port(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch)
    result = _invoke(eng_id, "--protocol", "https")
    assert result.exit_code == 1, result.stdout
    assert "requires --port" in result.stdout


def test_network_tool_requires_protocol(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch)
    result = _invoke(eng_id, "--port", "443")
    assert result.exit_code == 1, result.stdout
    assert "requires --protocol" in result.stdout


def test_explicit_ports_recorded(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch)
    result = _invoke(
        eng_id, "--port", "443", "--port", "8443",
        "--protocol", "https", "--method", "GET",
    )
    assert result.exit_code == 0, result.stdout
    assert "Ports: [443, 8443]" in result.stdout


def test_no_implicit_providers(tmp_path, monkeypatch):
    """Manifest declares providers, no --provider given -> approval has []."""
    eng_id = _setup(tmp_path, monkeypatch, providers=("crt.sh",))
    result = _invoke(
        eng_id, "--port", "443", "--protocol", "https", "--method", "GET",
    )
    assert result.exit_code == 0, result.stdout
    assert "Providers: (none)" in result.stdout
    assert "none were authorized" in result.stdout


def test_provider_must_be_declared_by_manifest(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch, providers=("crt.sh",))
    result = _invoke(
        eng_id, "--port", "443", "--protocol", "https", "--method", "GET",
        "--provider", "notamanifestthing",
    )
    assert result.exit_code == 1, result.stdout
    assert "not declared by manifest" in result.stdout


def test_provider_subset_accepted(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch, providers=("crt.sh",))
    result = _invoke(
        eng_id, "--port", "443", "--protocol", "https", "--method", "GET",
        "--provider", "crt.sh",
    )
    assert result.exit_code == 0, result.stdout
    assert "Providers: ['crt.sh']" in result.stdout


def test_intrusive_requires_yes(tmp_path, monkeypatch):
    """Without --yes, --intrusive prompts interactively. Non-interactive
    input (= Enter) defaults to 'no', so the command aborts."""
    eng_id = _setup(tmp_path, monkeypatch)
    result = runner.invoke(app, [
        "approval", "issue", eng_id,
        "--tool", "fake", "--version", "1.0",
        "--port", "443", "--protocol", "https", "--method", "GET",
        "--intrusive",
        "--actor", "op",
    ], input="n\n")
    assert result.exit_code == 1


def test_intrusive_with_yes(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch)
    result = _invoke(
        eng_id, "--port", "443", "--protocol", "https", "--method", "GET",
        "--intrusive", "--yes",
    )
    assert result.exit_code == 0, result.stdout
    assert "Intrusive: True" in result.stdout


def test_lab_requires_lab_platform(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch, platform="hackerone")
    result = _invoke(
        eng_id, "--port", "443", "--protocol", "https", "--method", "GET",
        "--lab",
    )
    assert result.exit_code == 1, result.stdout
    assert "requires engagement.platform='lab'" in result.stdout


def test_profile_must_be_in_manifest_allowed(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch, allowed_profiles=("scan",))
    result = _invoke(
        eng_id, "--port", "443", "--protocol", "https", "--method", "GET",
        "--profile", "notallowed",
    )
    assert result.exit_code == 1, result.stdout
    assert "not in manifest.allowed_profiles" in result.stdout


def test_path_restricted_requires_prefix(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch)
    result = _invoke(
        eng_id, "--port", "443", "--protocol", "https", "--method", "GET",
        "--path-profile", "restricted",
    )
    assert result.exit_code == 1, result.stdout
    assert "requires --path-prefix" in result.stdout


def test_policy_snapshot_must_exist(tmp_path, monkeypatch):
    eng_id = _setup(tmp_path, monkeypatch)
    result = _invoke(
        eng_id, "--port", "443", "--protocol", "https", "--method", "GET",
        "--policy-snapshot", "nonexistent-hash",
    )
    assert result.exit_code == 1, result.stdout
    assert "does not match" in result.stdout


def test_local_tool_no_port_required(tmp_path, monkeypatch):
    """Class 0 / no-network tools don't need --port/--protocol."""
    eng_id = _setup(
        tmp_path, monkeypatch, network=False,
        allowed_profiles=("python_static_analysis",),
    )
    result = _invoke(eng_id)
    assert result.exit_code == 0, result.stdout
    assert "Ports: []" in result.stdout
