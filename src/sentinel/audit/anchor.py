# SPDX-License-Identifier: Apache-2.0
"""External audit anchor. Gate 5 (§12.1)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .store import AuditStore


class AnchorFile:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def write_anchor(self, seq: int, head_hash: str) -> dict:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "seq": seq,
            "head_hash": head_hash,
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def last(self) -> dict | None:
        last = None
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = json.loads(line)
        return last


def verify_anchor(store: AuditStore, anchor: AnchorFile) -> tuple[bool, str]:
    last = anchor.last()
    if last is None:
        return True, "no anchor yet"
    row_hash = store.get_event_hash(last["seq"])
    if row_hash is None:
        return False, f"anchored seq {last['seq']} missing from DB — truncated"
    if row_hash != last["head_hash"]:
        return False, f"anchored seq {last['seq']} hash mismatch — tampered"
    return True, "ok"
