# SPDX-License-Identifier: Apache-2.0
"""Gitleaks adapter integration test against the pinned binary.

The adapter reads its manifest from the *test* database, so each test
must register the manifest into its own tmp_path DB before invoking
the adapter. This mirrors the real application flow: manifest
registration happens once per DB, not once per process.
"""

import hashlib
import os
from pathlib import Path

import pytest

from sentinel.storage.db import Database
from sentinel.engagement.store import EngagementStore
from sentinel.adapters.gitleaks import (
    run_gitleaks,
    AdapterError,
    GitleaksRunResult,
)
from sentinel.tools.manifests import ManifestStore, ToolManifest


BINARY = Path("tools/gitleaks").resolve()
pytestmark = pytest.mark.skipif(
    not BINARY.exists(),
    reason="tools/gitleaks binary missing",
)


def _register_manifest_in_db(db: Database) -> None:
    h = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    m = ToolManifest(
        tool_name="gitleaks",
        version="8.30.1",
        executable_path=str(BINARY),
        executable_sha256=h,
        execution_class=0,
        network_access=False,
        allowed_profiles=("local_source_secret_scan",),
        prohibited=("scanning_cloned_remote_repos",),
        limits={"max_runtime_seconds": 300, "max_output_megabytes": 25},
        output_format="json",
    )
    ManifestStore(db).register(m, actor="test")


def _write_synthetic_gitleaks_fixture(source_dir: Path) -> None:
    """Create scan canaries only inside the test's temporary directory."""
    source_dir.mkdir(parents=True, exist_ok=True)
    aws_key = "AK" + "IA" + "Z7Q2M9R4T6V8X3W5"
    github_token = "gh" + "p_" + ("B4n8Q2x6" * 5)
    jwt = (
        "eyJhbGciOi"
        + "JIUzI1NiJ9"
        + "."
        + "eyJzdWIiOi"
        + "J0ZXN0In0"
        + "."
        + "synthetic_signature_123456"
    )
    key_begin = "-----BEGIN " + "RSA " + "PRIVATE KEY-----"
    key_end = "-----END " + "RSA " + "PRIVATE KEY-----"
    key_body = "MIIEowIBAAKCAQEA" + "Z" * 48 + "\n" + "Q2Z7V4x9A6b3C8d1" * 4
    content = (
        "AWS_ACCESS_KEY_ID="
        + aws_key
        + "\n"
        + "GITHUB_TOKEN="
        + github_token
        + "\n"
        + "JWT="
        + jwt
        + "\n"
        + key_begin
        + "\n"
        + key_body
        + "\n"
        + key_end
        + "\n"
    )
    (source_dir / "synthetic_credentials.py").write_text(content, encoding="utf-8")


@pytest.fixture
def active_eng(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="gitleaks-fixture",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    # Generate scan input only under this test's temporary directory.
    src_dir = tmp_path / "engagements" / eng.id / "source"
    _write_synthetic_gitleaks_fixture(src_dir)

    # The persistent tool manifest is authoritative for registration.
    _register_manifest_in_db(db)

    yield db, eng.id, tmp_path / "engagements"
    db.close()


def test_gitleaks_manifest_is_class0_no_network(active_eng):
    db, _, _ = active_eng
    registered = ManifestStore(db).get_by_tool_version("gitleaks", "8.30.1")
    assert registered is not None
    assert registered.manifest.execution_class == 0
    assert registered.manifest.network_access is False


def test_happy_path(active_eng):
    db, eng_id, root = active_eng
    result = run_gitleaks(
        db,
        engagement_id=eng_id,
        engagements_root=root,
        scan_subdir="source",
        actor="op",
    )
    assert isinstance(result, GitleaksRunResult)
    assert result.findings_count >= 3
    assert result.process_exit_code == 0
    assert result.evidence.evidence_id.startswith("ev_")
    rules = {f.rule_id for f in result.findings}
    assert "private-key" in rules or "aws-access-token" in rules


def test_audit_event_written(active_eng):
    db, eng_id, root = active_eng
    result = run_gitleaks(
        db,
        engagement_id=eng_id,
        engagements_root=root,
        scan_subdir="source",
        actor="op",
    )
    row = db.connection.execute(
        "SELECT details_json FROM audit_events WHERE event_type = 'gitleaks_run'"
    ).fetchone()
    assert row is not None
    assert result.evidence.evidence_id in row["details_json"]


def test_evidence_redaction_status_is_held_or_redacted(active_eng):
    db, eng_id, root = active_eng
    r = run_gitleaks(
        db,
        engagement_id=eng_id,
        engagements_root=root,
        scan_subdir="source",
        actor="op",
    )
    assert r.evidence.redaction_status in ("clean", "redacted", "held_for_review")


def test_refuses_when_engagement_not_active(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="x",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    with pytest.raises(AdapterError, match="must be 'active'"):
        run_gitleaks(
            db,
            engagement_id=eng.id,
            engagements_root=tmp_path / "engagements",
            scan_subdir="source",
            actor="op",
        )
    db.close()


def test_refuses_on_missing_source(active_eng):
    db, eng_id, root = active_eng
    with pytest.raises(AdapterError, match="source does not exist"):
        run_gitleaks(
            db,
            engagement_id=eng_id,
            engagements_root=root,
            scan_subdir="does_not_exist",
            actor="op",
        )


def test_refuses_on_manifest_drift(active_eng):
    """Tamper the manifest_hash column; ManifestStore.verify() detects it."""
    db, eng_id, root = active_eng
    row = db.connection.execute(
        "SELECT id FROM tool_manifests WHERE tool_name='gitleaks'"
    ).fetchone()
    assert row is not None, "manifest should have been registered by fixture"

    with db.transaction() as conn:
        conn.execute(
            "UPDATE tool_manifests SET manifest_hash = 'deadbeef' WHERE id = ?",
            (row["id"],),
        )
    with pytest.raises(AdapterError, match="manifest DB drift"):
        run_gitleaks(
            db,
            engagement_id=eng_id,
            engagements_root=root,
            scan_subdir="source",
            actor="op",
        )


# --- Path containment (Gitleaks adapter preconditions, step 7) ---


def test_refuses_on_traversal(active_eng):
    """../other_engagement must be rejected as escaping the engagement dir."""
    db, eng_id, root = active_eng
    with pytest.raises(AdapterError, match="escapes engagement"):
        run_gitleaks(
            db,
            engagement_id=eng_id,
            engagements_root=root,
            scan_subdir="../other_engagement",
            actor="op",
        )


def test_refuses_on_absolute_path(active_eng):
    """Absolute scan_subdir bypasses engagement isolation entirely."""
    db, eng_id, root = active_eng
    with pytest.raises(AdapterError, match="escapes engagement"):
        run_gitleaks(
            db,
            engagement_id=eng_id,
            engagements_root=root,
            scan_subdir="/etc",
            actor="op",
        )


def test_refuses_on_symlink_escape(active_eng):
    """A symlink inside the engagement pointing outside must be rejected
    after .resolve() collapses it."""
    db, eng_id, root = active_eng
    eng_root = root / eng_id
    escape_link = eng_root / "escape_link"
    os.symlink("/etc", escape_link)
    try:
        with pytest.raises(AdapterError, match="escapes engagement"):
            run_gitleaks(
                db,
                engagement_id=eng_id,
                engagements_root=root,
                scan_subdir="escape_link",
                actor="op",
            )
    finally:
        escape_link.unlink(missing_ok=True)


def test_allows_nested_subdir_inside_engagement(active_eng):
    """Legitimate nested directories inside the engagement must still work.
    Guards against over-rejection of valid paths."""
    db, eng_id, root = active_eng
    nested = root / eng_id / "source" / "nested"
    nested.mkdir(parents=True, exist_ok=True)
    result = run_gitleaks(
        db,
        engagement_id=eng_id,
        engagements_root=root,
        scan_subdir="source/nested",
        actor="op",
    )
    assert result.process_exit_code == 0
    assert result.findings_count == 0  # empty nested dir
