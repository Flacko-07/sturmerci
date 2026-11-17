# SPDX-License-Identifier: Apache-2.0
"""Deny-by-default scope matching. Gate 1 + Gate 2."""
from __future__ import annotations

from .canonicalizer import CanonicalURL


def hostname_in_scope(hostname: str, scopes: list[dict]) -> bool:
    """A hostname matches iff it exactly equals a hostname scope or matches
    a wildcard scope with exactly one extra label to the left.

    Unknown / malformed / empty input -> False (deny by default).
    """
    if not hostname or not isinstance(hostname, str):
        return False
    host = hostname.lower().rstrip(".")
    for s in scopes:
        t = s.get("type")
        v = (s.get("value") or "").lower().rstrip(".")
        if not v:
            continue
        if t == "hostname":
            if host == v:
                return True
        elif t == "wildcard_hostname":
            if not v.startswith("*."):
                continue
            apex = v[2:]
            if host == apex:
                # Gate 1: wildcard does NOT match the apex
                continue
            if host.endswith("." + apex):
                prefix = host[: -(len(apex) + 1)]
                # Gate 1: wildcard matches exactly one label, not multi
                if prefix and "." not in prefix:
                    return True
    return False


def url_in_scope(url: CanonicalURL, scopes: list[dict]) -> bool:
    """A URL is in scope iff its scheme is http/https AND its host matches."""
    if url.scheme not in ("http", "https"):
        return False
    return hostname_in_scope(url.hostname, scopes)
