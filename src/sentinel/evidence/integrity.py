# SPDX-License-Identifier: Apache-2.0
"""Integrity checks for sanitized evidence consumed downstream."""

from __future__ import annotations

import hashlib
from pathlib import Path

from sentinel.audit.store import AuditStore
from sentinel.storage.db import Database


class EvidenceIntegrityError(ValueError):
    pass


def read_verified_sanitized(
    db: Database,
    *,
    artifact_id: str,
    engagement_id: str,
    sanitized_path: str,
    expected_sha256: str,
    expected_size: int,
    actor: str,
    consumer: str,
) -> bytes:
    """Read exact bytes and verify both recorded size and SHA-256.

    Any missing or altered artifact is audited before refusal. Callers must
    consume only the returned byte sequence, so the checked bytes and used
    bytes cannot diverge through a second path read.
    """
    try:
        payload = Path(sanitized_path).read_bytes()
        actual_hash = hashlib.sha256(payload).hexdigest()
        if len(payload) != expected_size or actual_hash != expected_sha256:
            raise EvidenceIntegrityError(
                f"sanitized evidence integrity mismatch for {artifact_id}"
            )
        return payload
    except (OSError, EvidenceIntegrityError) as exc:
        AuditStore(db).append(
            engagement_id=engagement_id,
            actor=actor,
            event_type="evidence_integrity_rejected",
            decision="denied",
            details={
                "artifact_id": artifact_id,
                "consumer": consumer,
                "expected_sha256": expected_sha256,
                "actual_sha256": locals().get("actual_hash"),
                "expected_size": expected_size,
                "actual_size": len(locals().get("payload", b"")),
                "reason": str(exc),
            },
        )
        if isinstance(exc, EvidenceIntegrityError):
            raise
        raise EvidenceIntegrityError(
            f"cannot read sanitized evidence {artifact_id}: {exc}"
        ) from exc
