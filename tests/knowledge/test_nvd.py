# SPDX-License-Identifier: Apache-2.0
"""NVD client tests — hermetic, mocked urlopen."""
from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.knowledge.nvd import (
    fetch_cve, store_cve, cve_exists, NvdError, NvdCve,
)
from sentinel.storage.db import Database


SAMPLE_NVD_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-99999",
                "published": "2024-06-15T10:00:00.000",
                "lastModified": "2024-08-01T12:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "en", "value": "Test vulnerability description."},
                    {"lang": "es", "value": "Descripción en español."},
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        }
                    }]
                },
            }
        }
    ]
}


class _FakeResp:
    def __init__(self, body: str):
        self._body = body.encode()
    def read(self):
        return self._body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def test_fetch_cve_parses_response():
    body = json.dumps(SAMPLE_NVD_RESPONSE)
    with patch("sentinel.knowledge.nvd.urllib.request.urlopen",
               return_value=_FakeResp(body)):
        cve = fetch_cve("CVE-2024-99999")
    assert cve.cve_id == "CVE-2024-99999"
    assert cve.vuln_status == "Analyzed"
    assert cve.description == "Test vulnerability description."
    assert cve.cvss_score == 7.5
    assert cve.cvss_severity == "HIGH"
    assert "CVE-2024-99999" in cve.raw_json


def test_fetch_cve_rejects_non_cve_id():
    with pytest.raises(NvdError, match="not a CVE ID"):
        fetch_cve("NOT-A-CVE")


def test_fetch_cve_handles_404_body():
    body = json.dumps({"totalResults": 0, "vulnerabilities": []})
    with patch("sentinel.knowledge.nvd.urllib.request.urlopen",
               return_value=_FakeResp(body)):
        with pytest.raises(NvdError, match="not found in NVD"):
            fetch_cve("CVE-2024-00000")


def test_store_and_exists(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite3")
    cve = NvdCve(
        cve_id="CVE-2024-1111",
        published_utc="2024-01-01T00:00:00",
        last_modified="2024-01-02T00:00:00",
        vuln_status="Analyzed",
        description="test desc",
        cvss_score=5.0,
        cvss_severity="MEDIUM",
        raw_json="{}",
    )
    assert not cve_exists(db, "CVE-2024-1111")
    store_cve(db, cve)
    assert cve_exists(db, "CVE-2024-1111")
    # Upsert doesn't error
    store_cve(db, cve)
    row = db.connection.execute(
        "SELECT COUNT(*) AS c FROM cve_entries WHERE cve_id='CVE-2024-1111'"
    ).fetchone()
    assert row["c"] == 1
    db.close()


def test_fetch_cve_no_engagement_data_leaked():
    """NVD request must contain ONLY the CVE ID — no engagement, no evidence."""
    captured = {}
    def _capture(req, timeout=20):
        captured["url"] = req.full_url if hasattr(req, "full_url") else str(req)
        body = json.dumps(SAMPLE_NVD_RESPONSE)
        return _FakeResp(body)

    with patch("sentinel.knowledge.nvd.urllib.request.urlopen", _capture):
        fetch_cve("CVE-2024-99999")

    assert "CVE-2024-99999" in captured["url"]
    # No engagement/evidence/target markers in URL
    for forbidden in ("engagement", "evidence", "target", "eng_"):
        assert forbidden not in captured["url"].lower()


def test_fetch_cve_429_is_transient_and_retries_bounded(monkeypatch):
    from sentinel.knowledge import nvd
    unavailable = urllib.error.HTTPError(
        nvd.NVD_API, 429, "rate limited", {}, None,
    )
    with patch("sentinel.knowledge.nvd.urllib.request.urlopen",
               side_effect=[unavailable, unavailable, unavailable]), \
         patch("sentinel.knowledge.nvd.time.sleep") as sleep:
        with pytest.raises(NvdError, match="after 3 attempts"):
            fetch_cve("CVE-2024-99999")
    assert sleep.call_count == 2


def test_fetch_cve_retries_503_without_marking_not_found():
    from sentinel.knowledge import nvd
    unavailable = urllib.error.HTTPError(
        nvd.NVD_API, 503, "maintenance", {}, None,
    )
    with patch("sentinel.knowledge.nvd.urllib.request.urlopen",
               side_effect=[unavailable, _FakeResp(json.dumps(SAMPLE_NVD_RESPONSE))]), \
         patch("sentinel.knowledge.nvd.time.sleep"):
        assert fetch_cve("CVE-2024-99999").vuln_status == "Analyzed"


def test_fetch_cve_timeout_is_transient():
    with patch("sentinel.knowledge.nvd.urllib.request.urlopen",
               side_effect=TimeoutError("network timeout")), \
         patch("sentinel.knowledge.nvd.time.sleep"):
        with pytest.raises(NvdError, match="failed after 3 attempts"):
            fetch_cve("CVE-2024-99999")


def test_fetch_cve_malformed_response_is_error_not_not_found():
    with patch("sentinel.knowledge.nvd.urllib.request.urlopen",
               return_value=_FakeResp("not-json")):
        with pytest.raises(NvdError, match="non-JSON"):
            fetch_cve("CVE-2024-99999")


def test_empty_response_without_total_results_is_not_invalid():
    with patch("sentinel.knowledge.nvd.urllib.request.urlopen",
               return_value=_FakeResp(json.dumps({"vulnerabilities": []}))):
        with pytest.raises(NvdError, match="authoritative totalResults=0"):
            fetch_cve("CVE-2024-00000")


def test_response_identifier_mismatch_is_error():
    response = json.loads(json.dumps(SAMPLE_NVD_RESPONSE))
    response["vulnerabilities"][0]["cve"]["id"] = "CVE-2024-00001"
    with patch("sentinel.knowledge.nvd.urllib.request.urlopen",
               return_value=_FakeResp(json.dumps(response))):
        with pytest.raises(NvdError, match="identifier mismatch"):
            fetch_cve("CVE-2024-99999")


def test_cve_exists_excludes_explicit_rejected_status(tmp_path):
    from sentinel.knowledge.nvd import mark_cve_invalid
    db = Database(tmp_path / "sentinel.sqlite3")
    mark_cve_invalid(db, "CVE-2024-1111", "authoritative not found")
    assert not cve_exists(db, "CVE-2024-1111")
    db.close()
