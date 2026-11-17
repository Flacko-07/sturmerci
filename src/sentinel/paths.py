# SPDX-License-Identifier: Apache-2.0
"""Filesystem layout for Sentinel. Engagement dirs get 0700."""

from __future__ import annotations

import os
from pathlib import Path


def _default_data_home() -> Path:
    """Return the XDG data home, falling back to ~/.local/share."""
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        candidate = Path(xdg).expanduser()
        if candidate.is_absolute():
            return candidate
    return Path.home() / ".local" / "share"


REPO_ROOT = Path(__file__).resolve().parents[2]


def _default_db_path() -> Path:
    override = os.environ.get("SENTINEL_DB_PATH")
    if override:
        return Path(override).expanduser()
    legacy_db = REPO_ROOT / "data" / "sentinel.sqlite3"
    if legacy_db.is_file():
        return legacy_db
    return _default_data_home() / "sturmercyberintelligence" / "sentinel.sqlite3"


def _default_engagements_path() -> Path:
    override = os.environ.get("SENTINEL_ENGAGEMENTS_ROOT")
    if override:
        return Path(override).expanduser()
    legacy_root = REPO_ROOT / "engagements"
    if legacy_root.is_dir():
        return legacy_root
    return _default_data_home() / "sturmercyberintelligence" / "engagements"


DEFAULT_DB = _default_db_path()
DEFAULT_ENGAGEMENTS_ROOT = _default_engagements_path()


def ensure_engagement_dirs(base_dir: Path, engagement_id: str) -> dict[str, Path]:
    if (
        not engagement_id.startswith("eng_")
        or "/" in engagement_id
        or ".." in engagement_id
    ):
        raise ValueError(f"unsafe engagement id: {engagement_id!r}")
    root = base_dir / engagement_id
    dirs = {
        "root": root,
        "artifacts": root / "artifacts",
        "artifacts_raw": root / "artifacts_raw",
        "findings": root / "findings",
        "reports": root / "reports",
        "logs": root / "logs",
    }
    for p in dirs.values():
        p.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass  # non-POSIX fs, best-effort
    return dirs
