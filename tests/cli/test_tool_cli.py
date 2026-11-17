# SPDX-License-Identifier: Apache-2.0
"""batch-7: tool manifest management CLI tests."""

from __future__ import annotations

import json

from typer.testing import CliRunner

import sentinel.cli as cli_mod
from sentinel.cli import app
from sentinel.storage.db import Database


runner = CliRunner()


def _setup(tmp_path, monkeypatch):
    db_path = tmp_path / "sentinel.sqlite3"
    monkeypatch.setattr(cli_mod, "_db", lambda: Database(db_path))
    return db_path


def _make_binary(tmp_path, content=b"fake-binary-content"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    p = bin_dir / "fake_tool"
    p.write_bytes(content)
    return p


def _invoke(*args):
    return runner.invoke(app, ["tool", *args])


# ====================================================================
# register
# ====================================================================


def test_register_creates_manifest(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path)
    result = _invoke(
        "register",
        str(binary),
        "--tool",
        "fake",
        "--version",
        "1.0.0",
        "--class",
        "2",
        "--network",
        "--profile",
        "scan",
        "--profile",
        "test",
        "--actor",
        "op",
    )
    assert result.exit_code == 0, result.stdout
    assert "Registered" in result.stdout
    assert "fake 1.0.0" in result.stdout

    db = Database(tmp_path / "sentinel.sqlite3")
    row = db.connection.execute(
        "SELECT execution_class, network_access FROM tool_manifests "
        "WHERE tool_name='fake'"
    ).fetchone()
    assert row["execution_class"] == 2
    assert row["network_access"] == 1
    db.close()


def test_register_refuses_missing_binary(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    result = _invoke(
        "register",
        str(tmp_path / "nonexistent"),
        "--tool",
        "fake",
        "--version",
        "1.0.0",
    )
    assert result.exit_code == 1
    assert "Binary not found" in result.stdout


def test_register_refuses_duplicate(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path)
    assert (
        _invoke(
            "register", str(binary), "--tool", "fake", "--version", "1.0.0"
        ).exit_code
        == 0
    )
    r2 = _invoke("register", str(binary), "--tool", "fake", "--version", "1.0.0")
    assert r2.exit_code == 1
    assert "Already registered" in r2.stdout


def test_register_refuses_bad_class(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path)
    result = _invoke(
        "register", str(binary), "--tool", "fake", "--version", "1.0.0", "--class", "9"
    )
    assert result.exit_code == 1
    assert "--class must be 0..3" in result.stdout


def test_register_warns_class2_without_network(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path)
    result = _invoke(
        "register", str(binary), "--tool", "fake", "--version", "1.0.0", "--class", "2"
    )
    assert result.exit_code == 0
    assert "Warning" in result.stdout
    assert "network is not set" in result.stdout


def test_register_records_provider_and_prohibited(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path)
    _invoke(
        "register",
        str(binary),
        "--tool",
        "fake",
        "--version",
        "1.0.0",
        "--provider",
        "crt.sh",
        "--provider",
        "otx",
        "--prohibited",
        "--script",
        "--prohibited",
        "-A",
    )
    db = Database(tmp_path / "sentinel.sqlite3")
    row = db.connection.execute(
        "SELECT infrastructure_endpoints_json, prohibited_json "
        "FROM tool_manifests WHERE tool_name='fake'"
    ).fetchone()
    assert set(json.loads(row["infrastructure_endpoints_json"])) == {"crt.sh", "otx"}
    assert set(json.loads(row["prohibited_json"])) == {"--script", "-A"}
    db.close()


# ====================================================================
# list
# ====================================================================


def test_list_empty(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    result = _invoke("list")
    assert result.exit_code == 0
    assert "No manifests registered" in result.stdout


def test_list_shows_registered(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path)
    _invoke(
        "register",
        str(binary),
        "--tool",
        "fake",
        "--version",
        "1.0.0",
        "--class",
        "2",
        "--network",
    )
    result = _invoke("list")
    assert result.exit_code == 0
    assert "fake 1.0.0" in result.stdout
    assert "class=2" in result.stdout


# ====================================================================
# verify
# ====================================================================


def test_verify_ok(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path)
    _invoke("register", str(binary), "--tool", "fake", "--version", "1.0.0")
    result = _invoke("verify", "fake", "1.0.0")
    assert result.exit_code == 0
    assert "Manifest row integrity OK" in result.stdout
    assert "Binary digest OK" in result.stdout


def test_verify_detects_binary_tampering(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path, b"original")
    _invoke("register", str(binary), "--tool", "fake", "--version", "1.0.0")
    binary.write_bytes(b"TAMPERED")
    result = _invoke("verify", "fake", "1.0.0")
    assert result.exit_code == 1
    assert "Binary digest MISMATCH" in result.stdout


def test_verify_refuses_missing_binary(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path)
    _invoke("register", str(binary), "--tool", "fake", "--version", "1.0.0")
    binary.unlink()
    result = _invoke("verify", "fake", "1.0.0")
    assert result.exit_code == 1
    assert "Binary missing" in result.stdout


def test_verify_refuses_unknown_tool(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    result = _invoke("verify", "nonexistent", "1.0.0")
    assert result.exit_code == 1
    assert "No manifest" in result.stdout


# ====================================================================
# deregister
# ====================================================================


def test_deregister_ok_with_yes(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    binary = _make_binary(tmp_path)
    _invoke("register", str(binary), "--tool", "fake", "--version", "1.0.0")
    result = _invoke("deregister", "fake", "1.0.0", "--yes")
    assert result.exit_code == 0
    assert "Deregistered" in result.stdout
    assert _invoke("verify", "fake", "1.0.0").exit_code == 1
