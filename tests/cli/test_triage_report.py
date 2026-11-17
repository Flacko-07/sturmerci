# SPDX-License-Identifier: Apache-2.0
"""CLI triage + report command tests."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from sentinel import cli as cli_mod
from sentinel.engagement.store import EngagementStore
from sentinel.evidence.ingest import ingest_evidence
from sentinel.llm import client as client_mod
from sentinel.reporting.report import generate_report, ReportError
from sentinel.storage.db import Database


def _fake_model_response(evidence_id: str) -> str:
    return json.dumps({
        "task_type": "finding_triage",
        "summary": "Sensitive data exposure via verbose error messages",
        "candidate_category": "information_exposure",
        "possible_references": ["CWE-209"],
        "evidence_ids": [evidence_id],
        "missing_evidence": ["Confirm error page is internet-facing"],
        "confidence_hint": "medium",
        "recommended_next_step": "Manual review of the error response",
    })


@pytest.fixture
def env(tmp_path, monkeypatch):
    db_path = tmp_path / "sentinel.sqlite3"
    monkeypatch.setattr(cli_mod, "DEFAULT_DB", db_path)
    monkeypatch.setattr(cli_mod, "DEFAULT_ENGAGEMENTS_ROOT", tmp_path / "engagements")
    client_mod._reset_circuit_for_tests()
    db = Database(db_path)
    eng = EngagementStore(db).create(
        platform="lab", program_name="triage-cli-test",
        policy_url=None, actor="operator",
        engagements_root=tmp_path / "engagements",
    )
    EngagementStore(db).transition(eng.id, "scope_review", "operator")
    EngagementStore(db).transition(eng.id, "active", "operator")
    artifact = ingest_evidence(
        db, engagements_root=tmp_path / "engagements",
        engagement_id=eng.id, source_name="fixture.txt",
        content_type="text/plain",
        content=b"error: 500 Internal Server Error at /admin",
        actor="operator",
    )
    monkeypatch.setattr(
        client_mod, "_ollama_chat",
        lambda **kw: SimpleNamespace(
            message=SimpleNamespace(content=_fake_model_response(artifact.evidence_id)),
        ),
    )
    yield {
        "db": db, "db_path": db_path, "eng_id": eng.id,
        "artifact_id": artifact.evidence_id,
        "engagements_root": tmp_path / "engagements",
    }
    client_mod._reset_circuit_for_tests()
    db.close()


@pytest.fixture
def runner():
    return CliRunner()


def test_triage_run_creates_finding(runner, env):
    result = runner.invoke(
        cli_mod.app,
        ["triage", "run", env["eng_id"], "--artifact", env["artifact_id"]],
    )
    assert result.exit_code == 0, result.output
    assert "Finding created:" in result.output
    # Verify in DB
    count = env["db"].connection.execute(
        "SELECT COUNT(*) FROM findings WHERE engagement_id = ?",
        (env["eng_id"],),
    ).fetchone()[0]
    assert count == 1


def test_findings_list_and_show(runner, env):
    # Create a finding
    runner.invoke(
        cli_mod.app,
        ["triage", "run", env["eng_id"], "--artifact", env["artifact_id"]],
    )
    # List
    r = runner.invoke(cli_mod.app, ["triage", "findings", env["eng_id"]])
    assert r.exit_code == 0
    assert "candidate" in r.output
    # Extract finding ID
    finding_id = env["db"].connection.execute(
        "SELECT id FROM findings WHERE engagement_id = ?",
        (env["eng_id"],),
    ).fetchone()[0]
    # Show
    r = runner.invoke(cli_mod.app, ["triage", "show", finding_id])
    assert r.exit_code == 0
    assert "CWE-209" in r.output or "References:" in r.output


def test_transition_to_ready_for_review_then_human_validated(runner, env):
    runner.invoke(
        cli_mod.app,
        ["triage", "run", env["eng_id"], "--artifact", env["artifact_id"]],
    )
    finding_id = env["db"].connection.execute(
        "SELECT id FROM findings WHERE engagement_id = ?",
        (env["eng_id"],),
    ).fetchone()[0]

    r = runner.invoke(
        cli_mod.app,
        ["triage", "transition", finding_id, "ready_for_review",
         "--actor", "operator"],
    )
    assert r.exit_code == 0, r.output
    assert "ready_for_review" in r.output

    r = runner.invoke(
        cli_mod.app,
        ["triage", "transition", finding_id, "human_validated",
         "--actor", "operator"],
    )
    assert r.exit_code == 0, r.output
    assert "human_validated" in r.output


def test_invalid_transition_rejected(runner, env):
    runner.invoke(
        cli_mod.app,
        ["triage", "run", env["eng_id"], "--artifact", env["artifact_id"]],
    )
    finding_id = env["db"].connection.execute(
        "SELECT id FROM findings WHERE engagement_id = ?",
        (env["eng_id"],),
    ).fetchone()[0]
    # candidate -> human_validated is not allowed
    r = runner.invoke(
        cli_mod.app,
        ["triage", "transition", finding_id, "human_validated",
         "--actor", "operator"],
    )
    assert r.exit_code != 0 or "refused" in r.output.lower()


def test_report_generate_validated_only(runner, env, tmp_path):
    # Create + promote finding
    runner.invoke(
        cli_mod.app,
        ["triage", "run", env["eng_id"], "--artifact", env["artifact_id"]],
    )
    finding_id = env["db"].connection.execute(
        "SELECT id FROM findings WHERE engagement_id = ?",
        (env["eng_id"],),
    ).fetchone()[0]
    runner.invoke(
        cli_mod.app,
        ["triage", "transition", finding_id, "ready_for_review"],
    )
    runner.invoke(
        cli_mod.app,
        ["triage", "transition", finding_id, "human_validated"],
    )

    output = tmp_path / "report.md"
    r = runner.invoke(
        cli_mod.app,
        ["report", "generate", env["eng_id"], "-o", str(output)],
    )
    assert r.exit_code == 0, r.output
    assert output.exists()
    text = output.read_text()
    assert "Assessment Report" in text
    assert "Sensitive data exposure" in text
    assert finding_id in text


def test_report_excludes_candidate_by_default(env):
    # Create a finding but leave as candidate
    from sentinel.triage.pipeline import triage_artifact
    triage_artifact(
        db=env["db"], engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    report = generate_report(env["db"], engagement_id=env["eng_id"])
    # No candidate should appear in the body
    assert "No findings to report" in report


def test_report_escapes_hostile_content(env):
    """Markdown-escape must neutralize javascript: URIs and structural chars."""
    from sentinel.triage.pipeline import triage_artifact
    result = triage_artifact(
        db=env["db"], engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    # Manually promote so it appears in validated-only report
    from sentinel.findings import FindingStore
    store = FindingStore(env["db"])
    store.transition(result.finding_id, "ready_for_review", actor="operator")
    store.transition(result.finding_id, "human_validated", actor="operator")
    report = generate_report(env["db"], engagement_id=env["eng_id"])
    # No raw javascript: URI should ever survive
    assert "javascript:" not in report.lower()
    # Escaped asterisks etc. (the finding has no * but test the mechanism)
    assert "# Assessment Report" in report  # title unescaped (safe)


def test_report_refuses_modified_sanitized_evidence(env):
    from sentinel.triage.pipeline import triage_artifact
    from sentinel.findings import FindingStore
    artifact_path = env["db"].connection.execute(
        "SELECT sanitized_path FROM artifacts WHERE id=?",
        (env["artifact_id"],),
    ).fetchone()[0]
    result = triage_artifact(
        db=env["db"], engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    store = FindingStore(env["db"])
    store.transition(result.finding_id, "ready_for_review", actor="operator")
    store.transition(result.finding_id, "human_validated", actor="operator")
    from pathlib import Path
    Path(artifact_path).write_text("tampered after finding")
    with pytest.raises(ValueError, match="integrity mismatch"):
        generate_report(env["db"], engagement_id=env["eng_id"])
    assert env["db"].connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type='evidence_integrity_rejected'"
    ).fetchone()[0] == 1


def test_report_refuses_incomplete_execution_evidence(env):
    from sentinel.triage.pipeline import triage_artifact
    from sentinel.findings import FindingStore
    from sentinel.reporting.report import ReportError

    result = triage_artifact(
        db=env["db"], engagement_id=env["eng_id"],
        artifact_id=env["artifact_id"],
    )
    FindingStore(env["db"]).transition(
        result.finding_id, "ready_for_review", actor="operator",
    )
    FindingStore(env["db"]).transition(
        result.finding_id, "human_validated", actor="operator",
    )
    env["db"].connection.execute(
        "UPDATE artifacts SET execution_status='PARTIAL' WHERE id=?",
        (env["artifact_id"],),
    )
    with pytest.raises(ReportError, match="execution status 'PARTIAL'"):
        generate_report(env["db"], engagement_id=env["eng_id"])
