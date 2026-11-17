# SPDX-License-Identifier: Apache-2.0
"""CLI smoke tests. Uses typer's CliRunner for in-process invocation."""

from __future__ import annotations


import pytest
from typer.testing import CliRunner

from sentinel import cli as cli_mod
from sentinel.storage.db import Database


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    """Redirect the CLI's DEFAULT_DB into a tmp dir for the test."""
    db_path = tmp_path / "sentinel.sqlite3"
    monkeypatch.setattr(cli_mod, "DEFAULT_DB", db_path)
    # Force creation + migrations
    db = Database(db_path)
    db.close()
    yield db_path


@pytest.fixture
def runner():
    return CliRunner()


def test_init_creates_db(runner, monkeypatch, tmp_path):
    db_path = tmp_path / "sentinel.sqlite3"
    monkeypatch.setattr(cli_mod, "DEFAULT_DB", db_path)
    result = runner.invoke(cli_mod.app, ["init"])
    assert result.exit_code == 0, result.output
    assert db_path.exists()


def test_status_shows_zero_counts(runner, temp_db):
    result = runner.invoke(cli_mod.app, ["status"])
    assert result.exit_code == 0, result.output
    assert "Engagements: 0" in result.output
    assert "Findings: 0" in result.output


def test_engagement_create_then_list(runner, temp_db):
    result = runner.invoke(
        cli_mod.app,
        [
            "engagement",
            "create",
            "--program",
            "test-prog",
            "--policy-url",
            "https://hackerone.com/test",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Created" in result.output
    # Now list
    result = runner.invoke(cli_mod.app, ["engagement", "list"])
    assert result.exit_code == 0
    assert "test-prog" in result.output


def test_scope_add_then_list(runner, temp_db):
    # Create engagement
    r = runner.invoke(
        cli_mod.app,
        ["engagement", "create", "--program", "test-prog"],
    )
    assert r.exit_code == 0
    # Extract engagement ID from output
    eng_id = None
    for line in r.output.splitlines():
        if "Created" in line and "eng_" in line:
            eng_id = line.split()[-1].strip("()").rstrip(")").split("(")[0]
            break
    # Fallback: query DB
    if eng_id is None or not eng_id.startswith("eng_"):
        db = Database(temp_db)
        eng_id = db.connection.execute("SELECT id FROM engagements LIMIT 1").fetchone()[
            0
        ]
        db.close()

    r = runner.invoke(
        cli_mod.app,
        ["scope", "add", eng_id, "--value", "app.test.example"],
    )
    assert r.exit_code == 0, r.output
    assert "In scope" in r.output

    r = runner.invoke(cli_mod.app, ["scope", "list", eng_id])
    assert r.exit_code == 0
    assert "app.test.example" in r.output
