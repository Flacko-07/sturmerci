# SPDX-License-Identifier: Apache-2.0
"""CVSS 4.0 calculator — deterministic base scoring via cvss package."""
from __future__ import annotations

import pytest

from sentinel.cvss.calculator import (
    calculate_cvss_4_0, CvssError, CvssResult,
)


LOG4SHELL_V40 = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
)


def test_log4shell_is_critical_10():
    r = calculate_cvss_4_0(LOG4SHELL_V40)
    assert isinstance(r, CvssResult)
    assert r.score == 10.0
    assert r.severity == "CRITICAL"
    assert r.valid is True
    assert r.vector == LOG4SHELL_V40


def test_severity_band_boundaries():
    from sentinel.cvss.calculator import _severity_from_score
    assert _severity_from_score(0.0) == "NONE"
    assert _severity_from_score(0.1) == "LOW"
    assert _severity_from_score(3.9) == "LOW"
    assert _severity_from_score(4.0) == "LOW"
    assert _severity_from_score(4.1) == "MEDIUM"
    assert _severity_from_score(7.0) == "MEDIUM"
    assert _severity_from_score(7.1) == "HIGH"
    assert _severity_from_score(9.0) == "HIGH"
    assert _severity_from_score(9.1) == "CRITICAL"
    assert _severity_from_score(10.0) == "CRITICAL"


def test_empty_vector_refused():
    with pytest.raises(CvssError, match="non-empty str"):
        calculate_cvss_4_0("")


def test_none_vector_refused():
    with pytest.raises(CvssError, match="non-empty str"):
        calculate_cvss_4_0(None)  # type: ignore[arg-type]


def test_non_string_vector_refused():
    with pytest.raises(CvssError, match="non-empty str"):
        calculate_cvss_4_0(42)  # type: ignore[arg-type]


def test_3_1_vector_refused():
    """Only CVSS 4.0 accepted. 3.1 vectors need a different calculator."""
    with pytest.raises(CvssError, match="CVSS:4.0"):
        calculate_cvss_4_0(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )


def test_malformed_vector_refused():
    with pytest.raises(CvssError, match="invalid CVSS 4.0"):
        calculate_cvss_4_0("CVSS:4.0/THIS/IS/NOT/A/VECTOR")


def test_missing_prefix_refused():
    with pytest.raises(CvssError, match="CVSS:4.0"):
        calculate_cvss_4_0("AV:N/AC:L/PR:N/UI:N")
