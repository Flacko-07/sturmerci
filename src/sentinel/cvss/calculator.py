# SPDX-License-Identifier: Apache-2.0
"""CVSS 4.0 base score calculator.

Thin wrapper around the RedHat `cvss` package (pinned in pyproject as
`cvss>=3.6`). That package implements the FIRST.org CVSS 4.0
macrovector lookup — 400+ entries from the spec appendix. We do NOT
reimplement it locally; transcription errors in a hand-rolled lookup
silently produce wrong scores, which is worse than a vendor
dependency.

Public surface:
    calculate_cvss_4_0(vector: str) -> CvssResult

Raises CvssError on malformed input or non-4.0 vectors. Never guesses —
an invalid vector returns an exception, not a zero score.
"""

from __future__ import annotations

from dataclasses import dataclass


class CvssError(ValueError):
    """Vector is malformed or not CVSS 4.0."""


@dataclass(frozen=True, slots=True)
class CvssResult:
    score: float
    severity: str
    vector: str
    valid: bool


# FIRST.org severity bands for CVSS 4.0 (same boundaries as 3.x).
_SEVERITY_BANDS = [
    (0.0, "NONE"),
    (4.0, "LOW"),
    (7.0, "MEDIUM"),
    (9.0, "HIGH"),
    (10.0, "CRITICAL"),
]


def _severity_from_score(score: float) -> str:
    """Map 0.0-10.0 to FIRST.org severity label.

    Bands (inclusive upper):
      0.0        NONE
      0.1 - 4.0  LOW
      4.1 - 7.0  MEDIUM
      7.1 - 9.0  HIGH
      9.1 - 10.0 CRITICAL
    """
    if score <= 0.0:
        return "NONE"
    for cutoff, label in _SEVERITY_BANDS:
        if cutoff == 0.0:
            continue
        if score <= cutoff:
            return label
    return "CRITICAL"


def calculate_cvss_4_0(vector: str) -> CvssResult:
    """Parse and score a CVSS 4.0 vector.

    Raises CvssError on malformed input or non-4.0 vectors.
    """
    if not vector or not isinstance(vector, str):
        raise CvssError(f"vector must be a non-empty str, got {vector!r}")
    v = vector.strip()
    if not v.startswith("CVSS:4.0/"):
        raise CvssError(f"only CVSS:4.0/ vectors are accepted, got {v[:40]!r}")
    try:
        from cvss import CVSS4

        parsed = CVSS4(v)
        score = float(parsed.base_score)
    except ImportError as e:
        raise CvssError(
            "cvss package not installed; install with "
            "`pip install cvss>=3.6` (supports CVSS 4.0)"
        ) from e
    except Exception as e:
        raise CvssError(f"invalid CVSS 4.0 vector {v!r}: {e}") from e

    return CvssResult(
        score=score,
        severity=_severity_from_score(score),
        vector=v,
        valid=True,
    )
