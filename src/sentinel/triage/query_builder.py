# SPDX-License-Identifier: Apache-2.0
"""Derive a KB search query from an artifact's metadata + content."""
from __future__ import annotations

import re


_IDENT_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+)\b", re.IGNORECASE)
_WORD_RE = re.compile(r"[A-Za-z]{3,}")


# Substring of source_name -> KB query. Priority order matters:
# more specific hints must come before generic ones.
_FILENAME_HINTS: list[tuple[str, str]] = [
    ("sqli", "SQL injection"),
    ("sql-injection", "SQL injection"),
    ("xss", "cross-site scripting"),
    ("bola", "broken object level authorization"),
    ("access-control", "access control authorization"),
    ("ssrf", "server side request forgery"),
    ("misconfig", "security misconfiguration"),
    ("sensitive-data", "sensitive data exposure"),
    # Adapter-specific hints. Keep these short -- the sanitizer AND-joins
    # tokens, so every word here must appear in at least one KB doc, or the
    # query returns zero hits. FTS5 unicode61 does not stem.
    ("gitleaks", "sensitive data exposure credentials"),
    ("nmap", "service exposure network scanning"),
    ("subfinder", "subdomain exposure reconnaissance"),
    ("httpx", "HTTP security headers misconfiguration"),
]


def build_kb_query(
    *,
    source_name: str,
    content_type: str,
    content: str,
) -> str:
    """Return a KB search query, or "" if nothing useful can be derived."""
    if content:
        idents = list(dict.fromkeys(_IDENT_RE.findall(content)))[:3]
        if idents:
            return " ".join(idents)

    name_lower = (source_name or "").lower()
    for token, hint in _FILENAME_HINTS:
        if token in name_lower:
            return hint

    sample = (content or "")[:500]
    words = _WORD_RE.findall(sample)
    seen: set[str] = set()
    kept: list[str] = []
    for w in words:
        wl = w.lower()
        if wl in seen:
            continue
        seen.add(wl)
        kept.append(w)
        if len(kept) >= 4:
            break
    return " ".join(kept)
