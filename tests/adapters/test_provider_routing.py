# SPDX-License-Identifier: Apache-2.0
"""Batch B: Scion and theHarvester send hostnames (not source IDs) as
provider_endpoints, and their manifests declare the same hostnames."""
from __future__ import annotations

import pytest


def test_scion_free_providers_are_hostnames():
    from sentinel.adapters.scion import SCION_FREE_PROVIDERS
    assert len(SCION_FREE_PROVIDERS) >= 5, SCION_FREE_PROVIDERS
    for p in SCION_FREE_PROVIDERS:
        assert "." in p, f"{p!r} not a hostname"
        assert "://" not in p, f"{p!r} has scheme prefix"
        assert "_" not in p, f"{p!r} has underscore"


def test_scion_request_uses_providers():
    """scion.py source must set provider_endpoints=SCION_FREE_PROVIDERS."""
    import sentinel.adapters.scion as scion_mod
    text = open(scion_mod.__file__).read()
    assert "provider_endpoints=SCION_FREE_PROVIDERS" in text, (
        "scion.py must pass SCION_FREE_PROVIDERS as provider_endpoints"
    )
    assert "provider_ports={p: 443 for p in SCION_FREE_PROVIDERS}" in text


def test_theharvester_source_to_host_map():
    from sentinel.adapters.theharvester import (
        SOURCE_TO_HOST, ALLOWED_PROVIDERS,
    )
    for src_id in ALLOWED_PROVIDERS:
        assert src_id in SOURCE_TO_HOST, (
            f"source {src_id!r} not in SOURCE_TO_HOST"
        )
        host = SOURCE_TO_HOST[src_id]
        assert "." in host, f"{src_id!r} -> {host!r} not a hostname"
        assert "://" not in host


def test_theharvester_request_uses_hostnames():
    """theharvester.py source must map source IDs to hostnames."""
    import sentinel.adapters.theharvester as harv_mod
    text = open(harv_mod.__file__).read()
    assert "SOURCE_TO_HOST[p] for p in providers" in text
    assert "provider_ports={SOURCE_TO_HOST[p]: 443 for p in providers}" in text
