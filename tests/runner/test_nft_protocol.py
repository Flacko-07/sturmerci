# SPDX-License-Identifier: Apache-2.0
"""Batch A: nft.add_approved supports protocol="udp"."""
from __future__ import annotations

import pytest

import sentinel.netns.nft as nft_mod


def test_add_approved_tcp_default(monkeypatch):
    calls = []
    monkeypatch.setattr(nft_mod, "_nft", lambda *args: calls.append(args))
    nft_mod.add_approved("8.8.8.8", 53, comment="test")
    rule = calls[-1]
    assert "tcp" in rule
    assert "dport" in rule
    idx = rule.index("tcp")
    assert rule[idx + 1] == "dport"
    assert rule[idx + 2] == "53"


def test_add_approved_udp(monkeypatch):
    calls = []
    monkeypatch.setattr(nft_mod, "_nft", lambda *args: calls.append(args))
    nft_mod.add_approved("8.8.8.8", 53, protocol="udp", comment="test")
    rule = calls[-1]
    assert "udp" in rule
    idx = rule.index("udp")
    assert rule[idx + 1] == "dport"
    assert rule[idx + 2] == "53"


def test_add_approved_bad_protocol(monkeypatch):
    monkeypatch.setattr(nft_mod, "_nft", lambda *a: None)
    with pytest.raises(ValueError, match="protocol"):
        nft_mod.add_approved("8.8.8.8", 53, protocol="sctp", comment="test")
