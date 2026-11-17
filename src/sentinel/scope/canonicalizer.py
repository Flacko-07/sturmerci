# SPDX-License-Identifier: Apache-2.0
"""
WHATWG-faithful URL canonicalization for Gate 1 scope decisions.

Boundary rule: any input this module cannot canonicalize cleanly must be
treated as DENY by the caller. This module does not decide scope; it
produces a normalized (hostname, scheme, port, path) tuple that the
matcher can compare against canonical scope entries.
"""
from __future__ import annotations

from dataclasses import dataclass

from ada_url import URL as AdaURL
from publicsuffixlist import PublicSuffixList

_psl = PublicSuffixList()

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


class CanonicalizationError(ValueError):
    """Raised when input cannot be safely canonicalized. Caller must DENY."""


@dataclass(frozen=True, slots=True)
class CanonicalURL:
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str


def canonicalize_url(raw: str) -> CanonicalURL:
    """Parse and canonicalize a URL. Raises CanonicalizationError on any doubt."""
    if not isinstance(raw, str) or not raw.strip():
        raise CanonicalizationError("empty or non-string input")
    if any(ord(ch) < 0x20 for ch in raw):
        raise CanonicalizationError("control characters in input")

    try:
        u = AdaURL(raw)
    except Exception as e:
        raise CanonicalizationError(f"parse failure: {e}") from e

    scheme = (u.protocol or "").rstrip(":").lower()
    # WHATWG preserves trailing dots in hostname; Gate 1 §4.2 requires
    # canonicalization to strip them. Do it here, not in the matcher.
    hostname = (u.hostname or "").rstrip(".").lower()
    path = u.pathname or "/"

    if scheme not in _DEFAULT_PORTS:
        raise CanonicalizationError(f"unsupported scheme: {scheme!r}")
    if not hostname:
        raise CanonicalizationError("missing hostname")

    port_raw = u.port
    port: int | None
    if port_raw in (None, ""):
        port = None
    else:
        try:
            port = int(port_raw)
        except ValueError as e:
            raise CanonicalizationError(f"invalid port: {port_raw!r}") from e
        if port == _DEFAULT_PORTS[scheme]:
            port = None

    return CanonicalURL(
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=u.search or "",
    )


def is_safe_wildcard(scope_value: str) -> bool:
    """Reject wildcard scope at or above a public suffix (e.g. *.com, *.co.uk).

    `*.example.com`, `*.api.example.com`, `*.sub.example.com` are all safe.
    Only the case where the domain IS a public suffix is rejected.
    """
    if not isinstance(scope_value, str):
        return False
    scope_value = scope_value.strip().lower()
    if not scope_value.startswith("*."):
        return False
    domain = scope_value[2:]
    if not domain or "." not in domain:
        return False
    suffix = _psl.publicsuffix(domain)
    if not suffix or suffix == domain:
        return False
    return True
