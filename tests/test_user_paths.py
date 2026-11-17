# SPDX-License-Identifier: Apache-2.0
from sentinel import paths


def test_default_paths_follow_xdg_data_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.delenv("SENTINEL_DB_PATH", raising=False)
    monkeypatch.delenv("SENTINEL_ENGAGEMENTS_ROOT", raising=False)

    monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)

    data_root = tmp_path / "xdg-data" / "sturmercyberintelligence"
    assert paths._default_db_path() == data_root / "sentinel.sqlite3"
    assert paths._default_engagements_path() == data_root / "engagements"


def test_explicit_sentinel_path_overrides_take_precedence(monkeypatch, tmp_path):
    db_path = tmp_path / "custom.sqlite3"
    engagement_root = tmp_path / "private-engagements"
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("SENTINEL_DB_PATH", str(db_path))
    monkeypatch.setenv("SENTINEL_ENGAGEMENTS_ROOT", str(engagement_root))

    assert paths._default_db_path() == db_path
    assert paths._default_engagements_path() == engagement_root


def test_existing_checkout_data_is_preserved(monkeypatch, tmp_path):
    legacy_db = tmp_path / "data" / "sentinel.sqlite3"
    legacy_db.parent.mkdir()
    legacy_db.touch()
    legacy_engagements = tmp_path / "engagements"
    legacy_engagements.mkdir()
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.delenv("SENTINEL_DB_PATH", raising=False)
    monkeypatch.delenv("SENTINEL_ENGAGEMENTS_ROOT", raising=False)
    monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)

    assert paths._default_db_path() == legacy_db
    assert paths._default_engagements_path() == legacy_engagements
