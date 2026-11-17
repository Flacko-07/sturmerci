# SPDX-License-Identifier: Apache-2.0
"""Engagement state machine."""

from __future__ import annotations

ALLOWED = {
    "draft": {"scope_review", "closed"},
    "scope_review": {"draft", "active", "closed"},
    "active": {"paused", "closed"},
    "paused": {"active", "closed"},
    "closed": set(),
}


class LifecycleError(ValueError):
    pass


def is_allowed(from_state: str, to_state: str) -> bool:
    return to_state in ALLOWED.get(from_state, set())
