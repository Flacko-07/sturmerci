# SPDX-License-Identifier: Apache-2.0
"""nuclei adapter test — hermetic, mocks run_in_sandbox."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import sentinel.runner.builtin_profiles  # noqa: F401
from sentinel.adapters.nuclei import (
    run_nuclei, parse_output, NucleiAdapterError, _verify_templates_dir,
)
from sentinel.approval.store import (
    ApprovalRecord, ApprovalStore, target_asset_ids_hash,
)
from sentinel.assets.store import AssetStore
from sentinel.engagement.store import EngagementStore
from sentinel.runner.profiles import build_argv_for_profile
from sentinel.runner.sandbox_runner import SandboxResult
from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


FAKE_JSONL = (
    '{"template-id":"git-config","info":{"name":"Git Config Exposure",'
    '"severity":"medium"},"host":"http://127.0.0.1:18080",'
    '"matched-at":"http://127.0.0.1:18080/.git/config","type":"http"}\n'
    '{"template-id":"phpmyadmin-panel","info":{"name":"phpMyAdmin Panel",'
    '"severity":"info"},"host":"http://127.0.0.1:18080",'
    '"matched-at":"http://127.0.0.1:18080/phpmyadmin/","type":"http"}\n'
    'not-json\n'
    '{"template-id":"ssl-weak","info":{"name":"Weak TLS","severity":"low"},'
    '"host":"127.0.0.1:18080","matched-at":"127.0.0.1:18080","type":"ssl"}\n'
)


def test_parse_output_skips_malformed():
    findings = parse_output(FAKE_JSONL)
    assert len(findings) == 3
    assert findings[0].template_id == "git-config"
    assert findings[0].severity == "medium"
    assert findings[2].type == "ssl"


def test_parse_output_empty():
    assert parse_output("") == []
    assert parse_output("\n\n") == []


def test_profile_builds_argv_with_blocklist():
    argv = build_argv_for_profile(
        profile_name="nuclei/scan",
        executable_path="/usr/local/bin/nuclei",
        params={"hostname": "127.0.0.1", "port": 18080, "scheme": "http",
                "rate_limit": 10, "timeout_seconds": 300},
    )
    assert "-jsonl" in argv and "-silent" in argv
    excl = argv[argv.index("-exclude-tags") + 1]
    for t in ("rce", "poc", "fuzz", "exploit", "sqli"):
        assert t in excl, f"blocklist missing {t}"
    # -headless and -code MUST NOT appear in argv. They are in the
    # prohibited list; relying on nuclei's defaults (both false) is
    # safer than passing the flags as =false, which the runner rejects.
    assert not any(a.startswith("-headless") for a in argv)
    assert not any(a.startswith("-code") for a in argv)
    assert "-disable-update-check" in argv


def test_profile_has_allow_tags():
    argv = build_argv_for_profile(
        profile_name="nuclei/scan",
        executable_path="/usr/local/bin/nuclei",
        params={"hostname": "127.0.0.1", "port": 18080, "scheme": "http",
                "rate_limit": 10, "timeout_seconds": 300},
    )
    tags = argv[argv.index("-tags") + 1]
    for t in ("exposure", "misconfig", "tech", "takeover", "ssl", "dns"):
        assert t in tags


def test_template_dir_missing_refused(tmp_path, monkeypatch):
    import sentinel.runner.builtin_profiles as bp
    monkeypatch.setattr(bp, "NUCLEI_TEMPLATES_DIR", str(tmp_path / "nope"))
    with pytest.raises(NucleiAdapterError, match="template dir missing"):
        _verify_templates_dir()


def test_template_dir_hash_mismatch_refused(tmp_path, monkeypatch):
    fake = tmp_path / "templates"
    (fake / "x").mkdir(parents=True)
    (fake / "x" / "a.yaml").write_text("id: a\n")
    import sentinel.runner.builtin_profiles as bp
    monkeypatch.setattr(bp, "NUCLEI_TEMPLATES_DIR", str(fake))
    monkeypatch.setattr(bp, "NUCLEI_TEMPLATES_HASH", "0" * 64)
    with pytest.raises(NucleiAdapterError, match="hash mismatch"):
        _verify_templates_dir()


def test_template_dir_matching_hash_accepted(tmp_path, monkeypatch):
    fake = tmp_path / "templates"
    (fake / "x").mkdir(parents=True)
    f = fake / "x" / "a.yaml"
    f.write_text("id: a\n")
    from sentinel.adapters.nuclei import _compute_templates_hash
    monkeypatch.setattr(
        "sentinel.runner.builtin_profiles.NUCLEI_TEMPLATES_DIR", str(fake),
    )
    monkeypatch.setattr(
        "sentinel.runner.builtin_profiles.NUCLEI_TEMPLATES_HASH",
        _compute_templates_hash(fake),
    )
    _verify_templates_dir()  # must not raise
