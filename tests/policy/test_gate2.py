# SPDX-License-Identifier: Apache-2.0
"""Gate 2: approval TTL denials."""
import pytest

from sentinel.approval.engine import calculate_approval_ttl


def test_short_window_raises():
    with pytest.raises(ValueError):
        calculate_approval_ttl(1800, 600)


def test_normal_case():
    # 1800 runtime + 300 margin = 2100; window 3600 permits it
    assert calculate_approval_ttl(1800, 3600) == 2100


def test_ttl_floor_at_900():
    # tiny runtime, large window -> floor applies
    assert calculate_approval_ttl(60, 3600) == 900


def test_negative_inputs_rejected():
    with pytest.raises(ValueError):
        calculate_approval_ttl(-1, 3600)
    with pytest.raises(ValueError):
        calculate_approval_ttl(60, -1)


def test_cap_at_3600():
    # long runtime that would exceed cap is allowed only if window permits,
    # but result never exceeds 3600
    assert calculate_approval_ttl(3000, 10000) == 3300
    assert calculate_approval_ttl(5000, 10000) == 3600
