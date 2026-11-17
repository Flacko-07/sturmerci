# SPDX-License-Identifier: Apache-2.0
"""Gate 5: audit chain integrity, external anchor, kill switch."""

import time

import psutil

from sentinel.audit.store import AuditStore
from sentinel.audit.anchor import AnchorFile, verify_anchor
from sentinel.runner.kill_switch import run_in_group, kill_group


# ---- Audit chain ----


def test_chain_appends_and_verifies(tmp_path):
    store = AuditStore(tmp_path / "a.db")
    store.append(engagement_id="e1", actor="op", event_type="open", decision="allow")
    store.append(engagement_id="e1", actor="op", event_type="lock", decision="allow")
    ok, at, reason = store.verify_chain()
    assert ok is True
    assert at is None
    store.close()


def test_chain_detects_deletion(tmp_path):
    store = AuditStore(tmp_path / "a.db")
    for i in range(5):
        store.append(
            engagement_id="e1", actor="op", event_type=f"e{i}", decision="allow"
        )
    store._db.connection.execute("DELETE FROM audit_events WHERE seq = 2")
    store._db.connection.commit()
    ok, at, _ = store.verify_chain()
    assert ok is False
    assert at == 3
    store.close()


def test_chain_detects_modification(tmp_path):
    store = AuditStore(tmp_path / "a.db")
    for i in range(3):
        store.append(
            engagement_id="e1", actor="op", event_type=f"e{i}", decision="allow"
        )
    store._db.connection.execute(
        "UPDATE audit_events SET decision='deny' WHERE seq = 1"
    )
    store._db.connection.commit()
    ok, at, _ = store.verify_chain()
    assert ok is False
    assert at == 1
    store.close()


# ---- External anchor ----


def test_anchor_passes_on_clean_db(tmp_path):
    store = AuditStore(tmp_path / "a.db")
    anchor = AnchorFile(tmp_path / "anchor.log")
    store.append(engagement_id="e1", actor="op", event_type="a", decision="allow")
    seq, head = store.head()
    anchor.write_anchor(seq, head)
    ok, reason = verify_anchor(store, anchor)
    assert ok is True, reason
    store.close()


def test_anchor_detects_db_replacement(tmp_path):
    store = AuditStore(tmp_path / "a.db")
    anchor = AnchorFile(tmp_path / "anchor.log")
    store.append(engagement_id="e1", actor="op", event_type="a", decision="allow")
    seq, head = store.head()
    anchor.write_anchor(seq, head)
    store.close()

    # Simulate attacker deleting and recreating the DB with different content
    (tmp_path / "a.db").unlink()
    store2 = AuditStore(tmp_path / "a.db")
    store2.append(
        engagement_id="e1", actor="attacker", event_type="cover", decision="allow"
    )
    ok, reason = verify_anchor(store2, anchor)
    assert ok is False
    assert "mismatch" in reason or "truncated" in reason
    store2.close()


# ---- Kill switch ----


def _is_dead(pid: int) -> bool:
    try:
        p = psutil.Process(pid)
        return p.status() in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD)
    except psutil.NoSuchProcess:
        return True


def test_kill_switch_terminates_parent_and_children():
    # sh backgrounds a sleep, then waits. killpg must take both.
    proc = run_in_group(["sh", "-c", "sleep 60 & wait"])
    try:
        time.sleep(0.3)
        kids = psutil.Process(proc.pid).children(recursive=True)
        assert kids, "expected at least one child (sleep)"
        child_pids = [k.pid for k in kids]

        start = time.monotonic()
        kill_group(proc, grace_seconds=1.5)
        # Wait for parent to exit
        try:
            proc.wait(timeout=3.0)
        except Exception:
            pass
        elapsed = time.monotonic() - start

        assert proc.poll() is not None, "parent survived kill_group"
        assert elapsed < 5.0, f"kill took {elapsed:.2f}s, exceeded 5s target"
        for cpid in child_pids:
            assert _is_dead(cpid), f"child {cpid} still alive after kill"
    finally:
        if proc.poll() is None:
            kill_group(proc, grace_seconds=0.5)
