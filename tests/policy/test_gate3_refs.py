# SPDX-License-Identifier: Apache-2.0
"""Gate 3: reference KB validation (G3-T03)."""

from sentinel.knowledge.refs import (
    is_structurally_valid,
    exists_in_kb,
    resolve_and_filter,
)
from sentinel.knowledge.nvd import NvdCve, mark_cve_invalid, store_cve
from sentinel.storage.db import Database


def test_valid_cwe_passes():
    assert exists_in_kb("CWE-79")
    assert exists_in_kb("CWE-284")


def test_structural_only_cwe_dropped():
    # CWE-99999 matches the pattern but is not in the KB
    assert is_structurally_valid("CWE-99999")
    assert not exists_in_kb("CWE-99999")


def test_owasp_api_passes():
    assert exists_in_kb("API1:2023")


def test_wstg_passes():
    assert exists_in_kb("WSTG-ATHN-01")


def test_masvs_passes():
    assert exists_in_kb("MASVS-STORAGE")


def test_cve_passes_structurally():
    assert exists_in_kb("CVE-2023-12345")


def test_garbage_rejected():
    assert not exists_in_kb("not a reference")
    assert not exists_in_kb("")


def test_filter_returns_kept_and_dropped():
    kept, dropped = resolve_and_filter(
        ["CWE-79", "CWE-99999", "API1:2023", "not-a-ref"]
    )
    assert kept == ["CWE-79", "API1:2023"]
    assert dropped == 2


def test_cve_cache_miss_remains_unverified(tmp_path):
    db = Database(tmp_path / "refs.sqlite3")
    statuses = {}
    details = {}
    kept, dropped = resolve_and_filter(
        ["CVE-2025-12345"],
        db=db,
        cve_statuses=statuses,
        reference_details=details,
    )
    assert kept == ["CVE-2025-12345"] and dropped == 0
    assert statuses["CVE-2025-12345"] == "unverified"
    assert details["CVE-2025-12345"]["lookup_outcome"] == "cache_miss"
    db.close()


def test_partial_cache_miss_remains_unverified(tmp_path):
    db = Database(tmp_path / "refs.sqlite3")
    store_cve(
        db,
        NvdCve(
            cve_id="CVE-2025-11111",
            published_utc="",
            last_modified="",
            vuln_status="Analyzed",
            description="",
            cvss_score=None,
            cvss_severity=None,
            raw_json="{}",
        ),
    )
    statuses = {}
    kept, dropped = resolve_and_filter(
        ["CVE-2025-22222"],
        db=db,
        cve_statuses=statuses,
    )
    assert kept == ["CVE-2025-22222"] and dropped == 0
    assert statuses["CVE-2025-22222"] == "unverified"
    db.close()


def test_cached_invalid_cve_is_not_verified(tmp_path):
    db = Database(tmp_path / "refs.sqlite3")
    mark_cve_invalid(db, "CVE-2025-12345", "authoritative absence")
    statuses = {}
    details = {}
    kept, dropped = resolve_and_filter(
        ["CVE-2025-12345"],
        db=db,
        cve_statuses=statuses,
        reference_details=details,
    )
    assert kept == [] and dropped == 1
    assert statuses["CVE-2025-12345"] == "invalid"
    assert details["CVE-2025-12345"]["rejection_reason"] == "authoritative absence"
    db.close()


def test_populated_cache_marks_cve_verified(tmp_path):
    db = Database(tmp_path / "refs.sqlite3")
    store_cve(
        db,
        NvdCve(
            cve_id="CVE-2025-12345",
            published_utc="",
            last_modified="",
            vuln_status="Analyzed",
            description="",
            cvss_score=None,
            cvss_severity=None,
            raw_json="{}",
        ),
    )
    statuses = {}
    kept, dropped = resolve_and_filter(
        ["CVE-2025-12345"],
        db=db,
        cve_statuses=statuses,
    )
    assert kept == ["CVE-2025-12345"] and dropped == 0
    assert statuses["CVE-2025-12345"] == "verified"
    db.close()
