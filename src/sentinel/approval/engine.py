# SPDX-License-Identifier: Apache-2.0
"""Approval TTL calculation. Gate 2."""
from __future__ import annotations


def calculate_approval_ttl(
    profile_max_runtime_sec: int,
    remaining_window_sec: int,
) -> int:
    """Return the approval TTL in seconds.

    Raises ValueError if the program window is too short to complete the
    profile plus a safety margin. Never silently truncates — truncation would
    allow a run to expire mid-execution.
    """
    if profile_max_runtime_sec < 0 or remaining_window_sec < 0:
        raise ValueError("runtime and window must be non-negative")
    margin_sec = 300
    required_sec = profile_max_runtime_sec + margin_sec
    if remaining_window_sec < required_sec:
        raise ValueError(
            "Program window too short for profile runtime + margin; deny."
        )
    return min(max(900, required_sec), 3600)
