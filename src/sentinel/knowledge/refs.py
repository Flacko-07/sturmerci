# SPDX-License-Identifier: Apache-2.0
"""Reference validation. Gate 3 (§6.2, G3-T03).

Structural pattern lives in models.contracts.ReferenceId. This module adds
existence checking against the local reference catalogue and NVD cache.
Uncached CVEs are retained as unverified; definitive rejected records are
excluded and their provenance is retained for review.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json

from sentinel.storage.db import Database

import re

_REFERENCE_PATTERN = re.compile(
    r"^(CWE-[0-9]{1,5}|"
    r"WSTG-[A-Z0-9][A-Z0-9-]{0,63}|"
    r"API[0-9]{1,2}:20[0-9]{2}|"
    r"MASVS-[A-Z0-9][A-Z0-9-]{0,63}|"
    r"CVE-[0-9]{4}-[0-9]{4,})$"
)

_KNOWN_CWE = {f"CWE-{n}" for n in (
    20, 22, 77, 78, 79, 89, 90, 94, 116, 200, 284, 287, 295, 306,
    352, 384, 400, 434, 444, 476, 502, 522, 601, 611, 613, 639,
    732, 798, 829, 862, 863, 918, 1021, 1173,
    209, 521, 770, 799, 915, 917, 942,
    209, 521, 770, 799, 915, 917, 942,
)}

_KNOWN_WSTG = {
    f"WSTG-{cat}-{n:02d}"
    for cat in ("INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS",
                "INPV", "ERRH", "CRYP", "BUSL", "CLNT", "APIT")
    for n in range(1, 20)
}

_KNOWN_API = {f"API{i}:2023" for i in range(1, 11)}

_KNOWN_MASVS = {f"MASVS-{x}" for x in (
    "STORAGE", "CRYPTO", "AUTH", "NETWORK",
    "PLATFORM", "CODE", "RESILIENCE", "PRIVACY",
)}

_KNOWN = _KNOWN_CWE | _KNOWN_WSTG | _KNOWN_API | _KNOWN_MASVS


def is_structurally_valid(ref: str) -> bool:
    return isinstance(ref, str) and _REFERENCE_PATTERN.match(ref) is not None


def exists_in_kb(ref: str) -> bool:
    """Structural validity plus existence. CVEs pass structurally only."""
    if not is_structurally_valid(ref):
        return False
    if ref.startswith("CVE-"):
        return True  # no bundled CVE DB; human review required downstream
    return ref in _KNOWN


class CveStatus(str):
    VERIFIED = "verified"       # NVD confirms this CVE exists
    UNVERIFIED = "unverified"   # not in cache; keep, tag for review
    INVALID = "invalid"         # NVD confirms this CVE does NOT exist


def resolve_and_filter(
    refs: list[str],
    db: Database | None = None,
    cve_statuses: dict[str, str] | None = None,
    reference_details: dict[str, dict] | None = None,
) -> tuple[list[str], int]:
    """Return (kept_references, dropped_count). Dropped refs are not errors
    in themselves; the caller records the count in model_runs.

    (v4.1 fix) CVE handling is now three-state, not binary:

      - VERIFIED:   cache hit. Keep.
      - UNVERIFIED: cache miss AND no definitive negative. Keep, tag.
      - INVALID:    operator has explicitly marked it invalid (NVD 404).
                    Drop.

    Prior behavior dropped any CVE absent from a partially populated
    cache. That discarded real CVEs that hadn't been synced yet — worse
    than hallucination because it silently suppressed valid references.

    `cve_statuses` (optional out-param) is populated with the status for
    every CVE checked, so the caller can persist it on the finding and
    surface "unverified" CVEs to the reviewer.
    """
    if cve_statuses is None:
        cve_statuses = {}
    if reference_details is None:
        reference_details = {}

    checked_at = datetime.now(timezone.utc).isoformat()

    def _cve_status(cve_ref: str) -> str:
        cve_ref = cve_ref.upper()
        if db is None:
            return CveStatus.UNVERIFIED
        try:
            # (v4.3 fix) Check vuln_status FIRST, not cve_exists().
            # cve_exists() returns True for any row regardless of status,
            # so a previously-committed INVALID row would return VERIFIED
            # and never reach the invalid branch. That made mark_cve_invalid
            # a no-op. Single query, single source of truth.
            row = db.connection.execute(
                "SELECT vuln_status, fetched_at_utc, raw_json "
                "FROM cve_entries WHERE cve_id = ?",
                (cve_ref,),
            ).fetchone()
            if row is None:
                reference_details[cve_ref] = {
                    "reference_type": "CVE", "status": CveStatus.UNVERIFIED,
                    "source": "local_nvd_cache", "checked_at_utc": checked_at,
                    "record_id": None, "lookup_outcome": "cache_miss",
                    "rejection_reason": None,
                }
                return CveStatus.UNVERIFIED
            status = (row["vuln_status"] or "").strip().upper()
            if status in {"INVALID", "REJECTED"}:
                reason = status
                try:
                    raw = json.loads(row["raw_json"] or "{}")
                    reason = str(raw.get("reason") or reason)
                except (TypeError, ValueError):
                    pass
                reference_details[cve_ref] = {
                    "reference_type": "CVE", "status": CveStatus.INVALID,
                    "source": "nvd_cache", "checked_at_utc": checked_at,
                    "record_id": cve_ref, "lookup_outcome": "rejected",
                    "rejection_reason": reason,
                }
                return CveStatus.INVALID
            reference_details[cve_ref] = {
                "reference_type": "CVE", "status": CveStatus.VERIFIED,
                "source": "nvd_cache", "checked_at_utc": checked_at,
                "record_id": cve_ref, "lookup_outcome": "cached_record",
                "rejection_reason": None,
            }
            return CveStatus.VERIFIED
        except Exception as exc:
            reference_details[cve_ref] = {
                "reference_type": "CVE", "status": CveStatus.UNVERIFIED,
                "source": "local_nvd_cache", "checked_at_utc": checked_at,
                "record_id": None,
                "lookup_outcome": f"cache_error:{type(exc).__name__}",
                "rejection_reason": None,
            }
            return CveStatus.UNVERIFIED

    kept: list[str] = []
    dropped = 0
    for original in refs:
        r = original.strip().upper() if isinstance(original, str) else ""
        if r.startswith("CVE-"):
            status = _cve_status(r)
            cve_statuses[original] = status
            if status == CveStatus.INVALID:
                dropped += 1
                continue
            kept.append(r)
        else:
            if exists_in_kb(r):
                kept.append(r)
                reference_details[original] = {
                    "reference_type": "CWE/WSTG/API/MASVS",
                    "status": CveStatus.VERIFIED,
                    "source": "local_reference_catalogue",
                    "checked_at_utc": checked_at, "record_id": r,
                    "lookup_outcome": "catalogue_match",
                    "rejection_reason": None,
                }
            else:
                dropped += 1
                reference_details[original] = {
                    "reference_type": "unknown",
                    "status": CveStatus.INVALID,
                    "source": "local_reference_catalogue",
                    "checked_at_utc": checked_at, "record_id": None,
                    "lookup_outcome": "no_catalogue_match",
                    "rejection_reason": "malformed_or_unknown_reference",
                }

    return kept, dropped
