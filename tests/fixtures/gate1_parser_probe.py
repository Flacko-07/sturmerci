# SPDX-License-Identifier: Apache-2.0
"""Gate 1 probe: verify canonicalizer produces correct normalized hostname."""

import sys

from sentinel.scope.canonicalizer import canonicalize_url, CanonicalizationError

CASES = [
    ("https://In-Scope.Example@evil.test./a/../b?x=1", "evil.test"),
    ("https://example.com@evil.test/", "evil.test"),
    ("https://2130706433/", "127.0.0.1"),
    ("https://example.com./path", "example.com"),
    ("https://example.com:443/", "example.com"),
    ("https://0x7f.0.0.1/", "127.0.0.1"),
    ("https://example.com.evil.test/", "example.com.evil.test"),
]

failures = []
for raw, expected in CASES:
    try:
        got = canonicalize_url(raw).hostname
        ok = got == expected
    except CanonicalizationError as e:
        got = f"<CanonicalizationError: {e}>"
        ok = False
    print(f"{raw!r:55} host={got!r:35} {'OK' if ok else 'FAIL'}")
    if not ok:
        failures.append((raw, expected, got))

if failures:
    print(f"\n{len(failures)} canonicalizer failure(s)", file=sys.stderr)
    for raw, exp, got in failures:
        print(f"  {raw!r}: expected {exp!r}, got {got!r}", file=sys.stderr)
    sys.exit(1)
print("\nAll canonicalizer cases pass.")
