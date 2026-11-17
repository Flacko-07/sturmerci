# SPDX-License-Identifier: Apache-2.0
"""End-to-end evidence ingestion. Gate 4 (§7) + evidence boundary."""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sentinel.storage.db import Database
from sentinel.engagement.store import EngagementStore
from sentinel.evidence.redact import (
    redact,
    assert_no_known_secrets,
)
from sentinel.audit.store import AuditStore


MAX_BYTES = 25 * 1024 * 1024

ALLOWED_CONTENT_TYPES = frozenset(
    {
        "application/json",
        "application/x-ndjson",
        "text/plain",
        "text/markdown",
        "text/csv",
        "text/xml",
        "application/xml",
        "application/yaml",
        "text/yaml",
        "application/x-python",
        "application/x-javascript",
        "text/x-python",
        "text/x-javascript",
        "text/x-source",
    }
)


class EvidenceRejected(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IngestResult:
    evidence_id: str
    engagement_id: str
    redaction_status: str
    unknown_format_triggered: bool
    rules_applied: dict[str, int]
    raw_sha256: str
    sanitized_sha256: str
    raw_size_bytes: int
    sanitized_size_bytes: int
    sanitized_path: str = ""
    execution_status: str = "COMPLETED"
    truncated_output: bool = False


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_file_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)


def ingest_evidence(
    db: Database,
    *,
    engagements_root: Path,
    engagement_id: str,
    source_name: str,
    content_type: str,
    content: bytes,
    actor: str,
    truncated_output: bool = False,
    execution_status: str = "COMPLETED",
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
    output_limit_bytes: int = 0,
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
    timed_out: bool = False,
    terminated: bool = False,
    process_exit_code: int | None = None,
    max_bytes: int = MAX_BYTES,
    allowed_content_types: frozenset[str] = ALLOWED_CONTENT_TYPES,
) -> IngestResult:
    if execution_status not in {"COMPLETED", "PARTIAL", "TIMED_OUT", "FAILED"}:
        raise EvidenceRejected(f"invalid execution_status: {execution_status!r}")
    if min(stdout_bytes, stderr_bytes, output_limit_bytes) < 0:
        raise EvidenceRejected("execution byte metadata must be non-negative")
    # 1. Engagement must exist and be active
    eng = EngagementStore(db).get(engagement_id)
    if eng is None:
        raise EvidenceRejected(f"engagement {engagement_id!r} not found")
    if eng.state != "active":
        raise EvidenceRejected(f"engagement state is {eng.state!r}; must be 'active'")

    # 2. Size
    if len(content) == 0:
        raise EvidenceRejected("empty content")
    if len(content) > max_bytes:
        raise EvidenceRejected(
            f"content too large ({len(content)} > {max_bytes} bytes)"
        )

    # 3. Content-type
    ct = content_type.split(";", 1)[0].strip().lower()
    if ct not in allowed_content_types:
        raise EvidenceRejected(f"content-type {content_type!r} not allowed")

    # 4. Must be UTF-8 text (binary rejects)
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise EvidenceRejected(f"content is not valid UTF-8: {e}") from e

    # 5. Redact
    sanitized, record = redact(text)

    # 6. Final barrier before persistence
    assert_no_known_secrets(sanitized)

    # 7. Decide status
    if record.unknown_format_triggered:
        redaction_status = "held_for_review"
    elif any(record.rules_applied.values()):
        redaction_status = "redacted"
    else:
        redaction_status = "clean"

    # 8. Hashes
    raw_sha = hashlib.sha256(content).hexdigest()
    sanitized_bytes = sanitized.encode("utf-8")
    sanitized_sha = hashlib.sha256(sanitized_bytes).hexdigest()

    # 9. Paths
    evidence_id = "ev_" + uuid.uuid4().hex[:16]
    root = engagements_root / engagement_id
    artifacts_dir = root / "artifacts"
    raw_dir = root / "artifacts_raw"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"{evidence_id}.raw"
    sanitized_path = artifacts_dir / f"{evidence_id}.txt"

    # 10. Persist atomically; on any failure, remove the files
    try:
        _write_file_atomic(raw_path, content)
        _write_file_atomic(sanitized_path, sanitized_bytes)

        with db.transaction() as conn:
            now = _iso_now()
            conn.execute(
                """INSERT INTO artifacts
                   (id, engagement_id, source_name, content_type,
                    raw_sha256, sanitized_sha256, raw_size_bytes, sanitized_size_bytes,
                    raw_path, sanitized_path, redaction_status, unknown_format_triggered,
                    truncated_output, actor, created_at_utc,
                    execution_status, stdout_bytes, stderr_bytes,
                    output_limit_bytes, stdout_truncated, stderr_truncated,
                    timed_out, terminated, process_exit_code)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence_id,
                    engagement_id,
                    source_name,
                    ct,
                    raw_sha,
                    sanitized_sha,
                    len(content),
                    len(sanitized_bytes),
                    str(raw_path),
                    str(sanitized_path),
                    redaction_status,
                    1 if record.unknown_format_triggered else 0,
                    1 if truncated_output else 0,
                    actor,
                    now,
                    execution_status,
                    stdout_bytes,
                    stderr_bytes,
                    output_limit_bytes,
                    1 if stdout_truncated else 0,
                    1 if stderr_truncated else 0,
                    1 if timed_out else 0,
                    1 if terminated else 0,
                    process_exit_code,
                ),
            )
            for rule_id, count in record.rules_applied.items():
                conn.execute(
                    """INSERT INTO artifact_redactions
                       (id, artifact_id, rule_id, category, count, decision,
                        rule_version, created_at_utc)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        "red_" + uuid.uuid4().hex[:16],
                        evidence_id,
                        rule_id,
                        rule_id,
                        count,
                        "redacted",
                        "v1",
                        now,
                    ),
                )
            AuditStore(db).append(
                engagement_id=engagement_id,
                actor=actor,
                event_type="evidence_ingested",
                decision=redaction_status,
                details={
                    "evidence_id": evidence_id,
                    "source_name": source_name,
                    "raw_sha256": raw_sha,
                    "sanitized_sha256": sanitized_sha,
                    "redaction_status": redaction_status,
                },
            )
    except Exception:
        raw_path.unlink(missing_ok=True)
        sanitized_path.unlink(missing_ok=True)
        raise

    return IngestResult(
        evidence_id=evidence_id,
        engagement_id=engagement_id,
        redaction_status=redaction_status,
        unknown_format_triggered=record.unknown_format_triggered,
        rules_applied=dict(record.rules_applied),
        raw_sha256=raw_sha,
        sanitized_sha256=sanitized_sha,
        raw_size_bytes=len(content),
        sanitized_size_bytes=len(sanitized_bytes),
        sanitized_path=str(sanitized_path),
        execution_status=execution_status,
        truncated_output=truncated_output,
    )
