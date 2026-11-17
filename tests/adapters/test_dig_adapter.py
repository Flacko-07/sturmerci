# SPDX-License-Identifier: Apache-2.0
"""dig adapter integration test — mocks run_in_sandbox."""

from __future__ import annotations

import hashlib

from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.engagement.store import EngagementStore
from sentinel.adapters.dig import (
    run_dig,
    parse_output,
    DigAdapterError,
)
from sentinel.runner.sandbox_runner import SandboxResult
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


FAKE_DIG_OUTPUT = """example.com.  3600  IN  A  93.184.216.34
example.com.  3600  IN  A  93.184.216.35
"""


def test_parse_answer_records():
    records = parse_output(FAKE_DIG_OUTPUT, "A")
    assert len(records) == 2
    assert records[0].name == "example.com"
    assert records[0].ttl == 3600
    assert records[0].value == "93.184.216.34"


def test_parse_filters_other_types():
    records = parse_output(FAKE_DIG_OUTPUT, "AAAA")
    assert records == []


def test_parse_skips_comment_lines():
    text = "; <<>> DiG <<>>\n; global options\n" + FAKE_DIG_OUTPUT
    records = parse_output(text, "A")
    assert len(records) == 2


def test_run_dig_mocked_happy_path(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    store = EngagementStore(db)
    eng = store.create(
        platform="lab",
        program_name="dig-test",
        policy_url=None,
        actor="op",
        engagements_root=tmp_path / "engagements",
    )
    store.transition(eng.id, "scope_review", "op")
    store.transition(eng.id, "active", "op")

    # Register a fake manifest in the TEMP db so the adapter's
    # ManifestStore lookup succeeds. Using /bin/true as the executable
    # means the test doesn't need the real `dig` binary installed.
    fake_binary = "/bin/true"
    h = hashlib.sha256(Path(fake_binary).read_bytes()).hexdigest()
    ManifestStore(db).register(
        ToolManifest(
            tool_name="dig",
            version="9.18.39",
            executable_path=fake_binary,
            executable_sha256=h,
            execution_class=2,
            network_access=True,
            allowed_profiles=("dns_lookup",),
            prohibited=("trace_mode", "batch_mode", "tcp_mode"),
            limits={"max_runtime_seconds": 60, "max_output_megabytes": 5},
            output_format="text",
        ),
        actor="test",
    )

    fake_sandbox = SandboxResult(
        stdout=FAKE_DIG_OUTPUT,
        stderr="",
        exit_code=0,
        duration_seconds=0.05,
        namespace_name="sentinel-run-test",
        resolved_ip="1.1.1.1",
        audit_event_seq=1,
        used_providers=("1.1.1.1",),
        resolved_ips=("1.1.1.1",),
    )
    with patch("sentinel.adapters.dig.run_in_sandbox", return_value=fake_sandbox):
        result = run_dig(
            db=db,
            engagement_id=eng.id,
            approval_id="appr_test",
            target_domain="example.com",
            resolver_ip="1.1.1.1",
            engagements_root=tmp_path / "engagements",
        )
    assert len(result.records) == 2
    assert result.evidence.evidence_id.startswith("ev_")
    db.close()


def test_refuses_non_ip_resolver():
    with pytest.raises(DigAdapterError, match="IP literal"):
        run_dig(
            db="/tmp/nonexistent.sqlite3",
            engagement_id="e",
            approval_id="a",
            target_domain="example.com",
            resolver_ip="dns.google",  # hostname, not IP
            engagements_root=Path("/tmp"),
        )


def test_refuses_forbidden_record_type():
    with pytest.raises(DigAdapterError, match="record_type"):
        run_dig(
            db="/tmp/nonexistent.sqlite3",
            engagement_id="e",
            approval_id="a",
            target_domain="example.com",
            resolver_ip="1.1.1.1",
            record_type="ANY",
            engagements_root=Path("/tmp"),
        )
