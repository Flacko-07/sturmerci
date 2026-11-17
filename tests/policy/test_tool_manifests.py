# SPDX-License-Identifier: Apache-2.0
"""Tool manifest registration and drift detection."""

import pytest

from sentinel.storage.db import Database
from sentinel.tools.manifests import ToolManifest, ManifestStore


def _manifest(**overrides):
    base = dict(
        tool_name="gitleaks",
        version="8.30.1",
        executable_path="tools/gitleaks",
        executable_sha256="deadbeef" * 8,
        execution_class=0,
        network_access=False,
        allowed_profiles=("local_source_secret_scan",),
        prohibited=("scanning_cloned_remote_repos",),
        limits={"max_runtime_seconds": 300, "max_output_megabytes": 25},
        output_format="json",
    )
    base.update(overrides)
    return ToolManifest(**base)


def test_register_and_get(tmp_path):
    db = Database(tmp_path / "x.db")
    store = ManifestStore(db)
    reg = store.register(_manifest(), actor="op")
    got = store.get(reg.id)
    assert got is not None
    assert got.manifest.tool_name == "gitleaks"
    assert got.manifest_hash == reg.manifest_hash
    db.close()


def test_duplicate_tool_version_rejected(tmp_path):
    db = Database(tmp_path / "x.db")
    store = ManifestStore(db)
    store.register(_manifest(), actor="op")
    with pytest.raises(Exception):
        store.register(_manifest(), actor="op")
    db.close()


def test_hash_changes_with_content(tmp_path):
    db = Database(tmp_path / "x.db")
    store = ManifestStore(db)
    a = store.register(_manifest(), actor="op")
    b = store.register(_manifest(version="8.31.0"), actor="op")
    assert a.manifest_hash != b.manifest_hash
    db.close()


def test_verify_detects_drift(tmp_path):
    """Simulate tamper: change the hash in the DB, verify fails."""
    db = Database(tmp_path / "x.db")
    store = ManifestStore(db)
    reg = store.register(_manifest(), actor="op")
    ok, _ = store.verify(reg.id)
    assert ok is True

    with db.transaction() as conn:
        conn.execute(
            "UPDATE tool_manifests SET executable_sha256 = 'tampered' WHERE id = ?",
            (reg.id,),
        )
    # Note: manifest_hash is unchanged in DB, so verify should detect that
    # the recomputed hash differs from stored manifest_hash.
    ok, reason = store.verify(reg.id)
    assert ok is False
    assert "drift" in reason.lower()
    db.close()
