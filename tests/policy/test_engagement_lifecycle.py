# SPDX-License-Identifier: Apache-2.0
"""Engagement lifecycle and directory creation."""

import os
import pytest

from sentinel.storage.db import Database
from sentinel.engagement.store import EngagementStore
from sentinel.engagement.lifecycle import is_allowed, LifecycleError


def _mk(tmp_path):
    db = Database(tmp_path / "x.db")
    store = EngagementStore(db)
    return db, store


def test_allowed_transitions():
    assert is_allowed("draft", "scope_review")
    assert is_allowed("scope_review", "active")
    assert is_allowed("active", "paused")
    assert is_allowed("paused", "active")
    assert is_allowed("active", "closed")
    assert not is_allowed("closed", "active")
    assert not is_allowed("draft", "active")  # must go through scope_review


def test_create_and_get(tmp_path):
    db, store = _mk(tmp_path)
    eng = store.create(
        platform="hackerone",
        program_name="prog",
        policy_url="https://x",
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    assert eng.state == "draft"
    assert eng.id.startswith("eng_")
    got = store.get(eng.id)
    assert got is not None and got.id == eng.id
    db.close()


def test_directories_created_and_restricted(tmp_path):
    db, store = _mk(tmp_path)
    eng = store.create(
        platform="lab",
        program_name="lab",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    root = tmp_path / "engagements" / eng.id
    for sub in ("artifacts", "artifacts_raw", "findings", "reports", "logs"):
        assert (root / sub).is_dir()
        assert oct(os.stat(root / sub).st_mode & 0o777) == "0o700"
    db.close()


def test_full_lifecycle(tmp_path):
    db, store = _mk(tmp_path)
    eng = store.create(
        platform="hackerone",
        program_name="p",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    for state in ("scope_review", "active", "paused", "active", "closed"):
        eng = store.transition(eng.id, state, actor="op")
        assert eng.state == state
    assert eng.closed_at_utc is not None
    db.close()


def test_illegal_transition_raises(tmp_path):
    db, store = _mk(tmp_path)
    eng = store.create(
        platform="hackerone",
        program_name="p",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    with pytest.raises(LifecycleError):
        store.transition(eng.id, "active", actor="op")  # must go via scope_review
    db.close()


def test_unsafe_engagement_id_rejected(tmp_path):
    with pytest.raises(ValueError):
        from sentinel.paths import ensure_engagement_dirs

        ensure_engagement_dirs(tmp_path, "eng_../../etc")
