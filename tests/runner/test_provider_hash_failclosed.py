# SPDX-License-Identifier: Apache-2.0
"""Batch A: _verify_provider_hash must fail-closed on empty stored hash
when providers are declared."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sentinel.approval.store import infrastructure_endpoints_hash
from sentinel.runner.sandbox_runner import (
    SandboxDenied,
    _verify_provider_hash,
)


def test_no_providers_no_check():
    """Empty providers list — nothing to verify, no raise."""
    approval = SimpleNamespace(
        approved_infrastructure_endpoints=[],
        approved_infrastructure_endpoints_hash="",
    )
    _verify_provider_hash(approval)  # no raise


def test_providers_with_empty_hash_refused():
    """Providers declared but hash empty → refuse fail-closed."""
    approval = SimpleNamespace(
        approved_infrastructure_endpoints=["crt.sh"],
        approved_infrastructure_endpoints_hash="",
    )
    with pytest.raises(SandboxDenied, match="empty"):
        _verify_provider_hash(approval)


def test_providers_with_matching_hash_ok():
    endpoints = ["crt.sh", "otx"]
    approval = SimpleNamespace(
        approved_infrastructure_endpoints=endpoints,
        approved_infrastructure_endpoints_hash=infrastructure_endpoints_hash(endpoints),
    )
    _verify_provider_hash(approval)  # no raise


def test_providers_with_wrong_hash_refused():
    approval = SimpleNamespace(
        approved_infrastructure_endpoints=["crt.sh"],
        approved_infrastructure_endpoints_hash="0" * 64,
    )
    with pytest.raises(SandboxDenied, match="mismatch"):
        _verify_provider_hash(approval)
