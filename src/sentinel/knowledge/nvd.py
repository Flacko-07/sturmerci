# SPDX-License-Identifier: Apache-2.0
"""NVD API 2.0 client — single-CVE fetch with local cache.

Scope: single-CVE sync for validator support. Bulk/incremental sync,
CWE, CAPEC, and ATT&CK STIX are separate work items.

No API key: NVD rate-limits to 5 requests / 30 s unauthenticated.
This client does one request per call; operators sync a small list at
a time. Rate-limit handling (429 + Retry-After) is implemented but
retries are bounded to 3 to avoid hangs on a stuck endpoint.

No target-data egress: the client only sends the CVE ID being looked
up. No engagement id, no evidence, no scan output.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from sentinel.storage.db import Database


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 6.0  # NVD unauthenticated = 5 req/30s
_CVE_ID_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.IGNORECASE)


class NvdError(RuntimeError):
    pass


class NvdCveNotFound(NvdError):
    """NVD returned 0 vulnerabilities for the queried CVE ID."""
    pass


@dataclass(frozen=True, slots=True)
class NvdCve:
    cve_id: str
    published_utc: str
    last_modified: str
    vuln_status: str
    description: str
    cvss_score: float | None
    cvss_severity: str | None
    raw_json: str
    # (v4.1) CVSS version + vector preserved even when we can't compute
    # a score locally (e.g. CVSS 4.0 today). Downstream CVSS calculator
    # can act on these without re-fetching from NVD. Defaults are None
    # so existing NvdCve(...) constructions keep working.
    cvss_version: str | None = None
    cvss_vector: str | None = None


def _parse_nvd(cve_id: str, obj: dict) -> NvdCve:
    cve = obj.get("cve") or {}
    descs = cve.get("descriptions") or []
    desc = ""
    for d in descs:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc and descs:
        desc = descs[0].get("value", "")

    cvss_score: float | None = None
    cvss_sev: str | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    metrics = cve.get("metrics") or {}
    # Preference order: CVSS 4.0 > 3.1 > 3.0 > 2.0. Each array is
    # [{'cvssData': {...}, 'type': 'Primary'|'Secondary'}, ...]; we
    # prefer the Primary entry if present.
    for key, version_tag in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        arr = metrics.get(key) or []
        if not arr:
            continue
        chosen = next(
            (a for a in arr if a.get("type") == "Primary"), arr[0]
        )
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, (int, float)):
            cvss_score = float(score)
        sev = data.get("baseSeverity")
        if isinstance(sev, str):
            cvss_sev = sev
        cvss_version = version_tag
        vector = data.get("vectorString")
        if isinstance(vector, str):
            cvss_vector = vector
        break

    return NvdCve(
        cve_id=str(cve.get("id", cve_id)),
        published_utc=str(cve.get("published", "")),
        last_modified=str(cve.get("lastModified", "")),
        vuln_status=str(cve.get("vulnStatus", "")),
        description=desc[:2000],
        cvss_score=cvss_score,
        cvss_severity=cvss_sev,
        cvss_version=cvss_version,
        cvss_vector=cvss_vector,
        raw_json=json.dumps(obj, sort_keys=True, separators=(",", ":")),
    )


def fetch_cve(cve_id: str) -> NvdCve:
    """Fetch one CVE from NVD API 2.0. Raises NvdError on failure."""
    if not isinstance(cve_id, str) or not _CVE_ID_RE.fullmatch(cve_id):
        raise NvdError(f"not a CVE ID: {cve_id!r}")
    url = f"{NVD_API}?cveId={cve_id.upper()}"
    last_err: str | None = None
    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "sentinel-nvd-sync/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                body = r.read().decode("utf-8", errors="replace")
            data = json.loads(body)
        except urllib.error.HTTPError as e:
            # Retry on transient failures: 429 rate-limit + 5xx server-side.
            # NVD's API 2.0 returns 503 during maintenance windows and
            # occasional 502/500 under load. A single-attempt failure
            # produces a noisy operator experience for what is almost
            # always a 5-second outage. The 3-attempt, 6-second-backoff
            # budget is the same as 429 — cheap and bounded.
            if e.code == 429 or 500 <= e.code < 600:
                last_err = f"HTTP {e.code} {e.reason}"
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_BACKOFF_SECONDS)
                    continue
                raise NvdError(
                    f"NVD returned {e.code} for {cve_id} after "
                    f"{MAX_RETRIES} attempts: {e.reason}"
                ) from e
            raise NvdError(f"NVD HTTP {e.code} for {cve_id}: {e.reason}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_BACKOFF_SECONDS)
            continue
        except json.JSONDecodeError as e:
            raise NvdError(f"NVD returned non-JSON for {cve_id}: {e}") from e

        if not isinstance(data, dict):
            raise NvdError(f"NVD returned malformed JSON object for {cve_id}")
        vulns = data.get("vulnerabilities")
        total = data.get("totalResults")
        if not isinstance(vulns, list):
            raise NvdError(f"NVD response missing vulnerabilities list for {cve_id}")
        if not vulns:
            if total == 0:
                raise NvdCveNotFound(f"CVE {cve_id} not found in NVD")
            raise NvdError(
                f"NVD response for {cve_id} had no vulnerabilities without "
                "an authoritative totalResults=0 result"
            )
        if not isinstance(vulns[0], dict) or not isinstance(vulns[0].get("cve"), dict):
            raise NvdError(f"NVD response contains malformed CVE record for {cve_id}")
        returned_id = str(vulns[0]["cve"].get("id", "")).upper()
        if returned_id != cve_id.upper():
            raise NvdError(
                f"NVD response identifier mismatch for {cve_id}: {returned_id!r}"
            )
        return _parse_nvd(cve_id, vulns[0])

    raise NvdError(f"NVD fetch for {cve_id} failed after {MAX_RETRIES} attempts: {last_err}")


def store_cve(db: Database, cve: NvdCve) -> None:
    """Upsert a CVE into the local cache."""
    now = datetime.now(timezone.utc).isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO cve_entries
               (cve_id, published_utc, last_modified, vuln_status,
                description, cvss_score, cvss_severity, raw_json,
                fetched_at_utc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                published_utc=excluded.published_utc,
                last_modified=excluded.last_modified,
                vuln_status=excluded.vuln_status,
                description=excluded.description,
                cvss_score=excluded.cvss_score,
                cvss_severity=excluded.cvss_severity,
                raw_json=excluded.raw_json,
                fetched_at_utc=excluded.fetched_at_utc""",
            (cve.cve_id, cve.published_utc, cve.last_modified,
             cve.vuln_status, cve.description, cve.cvss_score,
             cve.cvss_severity, cve.raw_json, now),
        )


def cve_exists(db: Database, cve_id: str) -> bool:
    row = db.connection.execute(
        "SELECT 1 FROM cve_entries WHERE cve_id = ? "
        "AND UPPER(vuln_status) NOT IN ('INVALID','REJECTED')",
        (cve_id.upper(),),
    ).fetchone()
    return row is not None


def mark_cve_invalid(db: Database, cve_id: str, reason: str) -> None:
    """Mark a CVE as confirmed-invalid (NVD returned 404).

    Inserts a stub row with vuln_status='INVALID' so the three-state
    reference validator treats it as INVALID rather than UNVERIFIED.
    This is the ONLY path that authorizes dropping a CVE reference.
    """
    now = datetime.now(timezone.utc).isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO cve_entries
               (cve_id, published_utc, last_modified, vuln_status,
                description, cvss_score, cvss_severity, raw_json,
                fetched_at_utc)
               VALUES (?, '', '', 'INVALID', ?, NULL, NULL, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                vuln_status='INVALID',
                description=excluded.description,
                fetched_at_utc=excluded.fetched_at_utc""",
            (
                cve_id.upper(),
                f"Confirmed invalid: {reason}",
                '{"vuln_status": "INVALID", "reason": '
                + json.dumps(reason) + '}',
                now,
            ),
        )


def record_sync_attempt(
    db: Database, *, cve_id: str, outcome: str, actor: str,
    detail: str, record_status: str | None = None,
) -> None:
    """Persist an operator-visible NVD result without changing CVE truth."""
    if outcome not in {"verified", "rejected", "not_found", "transient_error"}:
        raise ValueError(f"unsupported NVD sync outcome: {outcome!r}")
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO cve_sync_attempts "
            "(attempt_id,cve_id,outcome,attempted_at_utc,actor,detail,record_status) "
            "VALUES (?,?,?,?,?,?,?)",
            ("nvd_" + uuid4().hex[:20], cve_id.upper(), outcome,
             datetime.now(timezone.utc).isoformat(), actor, detail[:2000],
             record_status),
        )
