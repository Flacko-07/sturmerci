# SPDX-License-Identifier: Apache-2.0
"""Redaction pipeline. Gate 4.

Every artifact must pass through `redact()` before any of its content is
assembled into an LLM prompt. The return value carries both the sanitized
text and an audit record. The audit record never contains the secret value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(slots=True)
class RedactionRecord:
    rules_applied: dict[str, int] = field(default_factory=dict)
    unknown_format_triggered: bool = False

    def bump(self, rule_id: str) -> None:
        self.rules_applied[rule_id] = self.rules_applied.get(rule_id, 0) + 1


# Ordered patterns. Order matters: broad patterns go after narrow ones.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Gitleaks-style context-preserving redaction: REDACTED followed by
    # the last few characters of the secret as a fingerprint. Collapse
    # the suffix so no fragment of the original secret survives.
    ("redacted_suffix", re.compile(r"\bREDACTED[A-Za-z0-9_\-]{2,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("generic_bearer", re.compile(r"\bBearer\s+[A-Za-z0-9\-_.=]{20,}\b")),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----.*?"
            r"-----END (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("cookie_header", re.compile(r"(?im)^Cookie:\s*.*$")),
    ("set_cookie_header", re.compile(r"(?im)^Set-Cookie:\s*.*$")),
    ("auth_header", re.compile(r"(?im)^Authorization:\s*.*$")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
]

_PLACEHOLDER = "[REDACTED:{rule_id}]"


# Heuristic: a long unbroken token of mixed case+digits+symbols that did
# not match any rule is treated as unknown-format sensitive data and
# replaced with a placeholder, with the record flagging that human review
# is required before the artifact is used.
# (Bug 4 fix, corrected) The character class includes `/` (needed for
# base64), so a long path like `engagements/eng_x/source/_helpers` matched
# as a 49-char token and was redacted — leaving `.py` behind as
# `[REDACTED:unknown_long_token].py`.
#
# The initial fix used only a negative lookahead `(?!\.(?:ext))`, but
# regex backtracking defeated it: `{40,}` could match a SHORTER prefix
# (`.../_helper`), and `s.py` following the prefix doesn't start with
# `.py` — so the lookahead passed. The path was still redacted.
#
# Atomic group `(?>...)` (Python 3.11+) disables backtracking inside the
# group: the character class must match the full run up to its natural
# boundary. Then the lookahead fires at the correct position.
_FILE_EXTENSIONS = (
    "py",
    "js",
    "ts",
    "tsx",
    "jsx",
    "go",
    "rs",
    "java",
    "rb",
    "php",
    "sh",
    "bash",
    "zsh",
    "ps1",
    "pl",
    "lua",
    "kt",
    "swift",
    "c",
    "h",
    "cpp",
    "hpp",
    "cs",
    "scala",
    "clj",
    "ex",
    "exs",
    "json",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "env",
    "xml",
    "html",
    "htm",
    "css",
    "scss",
    "less",
    "svg",
    "md",
    "txt",
    "log",
    "lock",
    "csv",
    "tsv",
    "sql",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "pdf",
    "zip",
    "tar",
    "gz",
)
_EXT_ALT = "|".join(_FILE_EXTENSIONS)
_UNKNOWN_LONG_TOKEN = re.compile(
    rf"(?>[A-Za-z0-9+/=_\-]{{40,}})(?!\.(?:{_EXT_ALT})(?:\b|$))"
)


def redact(text: str) -> tuple[str, RedactionRecord]:
    """Return (sanitized_text, record). Never returns the original secret."""
    if not isinstance(text, str):
        raise TypeError("redact() requires str")
    record = RedactionRecord()
    out = text
    for rule_id, pat in _PATTERNS:

        def _sub(m, _rid=rule_id):
            record.bump(_rid)
            return _PLACEHOLDER.format(rule_id=_rid)

        out = pat.sub(_sub, out)

    # Unknown-format defense: long token that survived known rules.
    def _unknown(m):
        record.unknown_format_triggered = True
        record.bump("unknown_long_token")
        return _PLACEHOLDER.format(rule_id="unknown_long_token")

    out = _UNKNOWN_LONG_TOKEN.sub(_unknown, out)

    return out, record


def assert_no_known_secrets(text: str) -> None:
    """Defensive check: raise if any known secret shape is still present.
    Used by the prompt-assembly code as a final barrier before the model."""
    for rule_id, pat in _PATTERNS:
        if pat.search(text):
            raise RuntimeError(f"Gate 4 violation: {rule_id} survived redaction")
