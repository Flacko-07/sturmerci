# SPDX-License-Identifier: Apache-2.0
"""Approval record and SQLite store. Gate 2."""

from __future__ import annotations

from sentinel.storage.db import Database, coerce_db

import hashlib
import json
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path


def _uuid() -> str:
    return "appr_" + uuid.uuid4().hex


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def target_asset_ids_hash(ids: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(sorted(ids), separators=(",", ":")).encode()
    ).hexdigest()


def infrastructure_endpoints_hash(endpoints: list[str]) -> str:
    """Deterministic hash of the approved provider list.

    Empty list produces a stable hash (not the empty string) so that
    "approved no providers" is a distinct, verifiable state rather than
    "the field was never populated".
    """
    return hashlib.sha256(
        json.dumps(sorted(endpoints), separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    engagement_id: str
    engagement_state_at_issue: str
    policy_snapshot_hash: str
    scope_lock_hash: str
    target_asset_ids: list[str]
    target_asset_ids_hash: str
    canonical_hostnames: list[str]
    allowed_ports: list[int]
    allowed_protocols: list[str]
    allowed_http_methods: list[str]
    allowed_path_profile: str
    operation_profile_id: str
    tool_name: str
    tool_version: str
    tool_executable_sha256: str
    adapter_code_sha256: str
    manifest_hash: str
    egress_profile_id: str
    normalized_arguments_hash: str
    # (6A) Operator-declared profile params, captured at issue time.
    # Empty dict = no param binding (backwards-compatible).
    # kw_only=True keeps it out of positional field ordering, which
    # would otherwise break because later fields (request_rate_budget,
    # etc.) have no defaults.
    profile_params: dict = field(default_factory=dict, kw_only=True)
    request_rate_budget: int
    aggregate_request_budget: int
    aggregate_byte_budget: int
    concurrency_budget: int
    aggregate_runtime_budget: int
    aggregate_model_token_budget: int
    issued_by: str
    issued_at_utc: str
    expires_at_utc: str
    # Providers the operator authorized for this engagement, e.g.
    # ["crt.sh"]. Must be a subset of the manifest's declared
    # infrastructure_endpoints, and a superset of each run's
    # request.provider_endpoints. Empty is the default (no providers).
    approved_infrastructure_endpoints: list[str] = field(default_factory=list)
    approved_infrastructure_endpoints_hash: str = ""
    # M7.2c: prefixes enforced when allowed_path_profile != "default".
    # Ignored in default mode. Restricted mode with empty list is a
    # configuration error and SandboxRunner refuses it.
    allowed_path_prefixes: list[str] = field(default_factory=list)
    # Operator must affirmatively set this True to authorize port scanning
    # of the resolved infrastructure (not just the hostname).
    # Nmap refuses to run if this is False.
    port_scanning_authorized: bool = False
    # ECR v1.0.2: Class 3 authorization
    intrusive_authorized: bool = False
    lab_environment: bool = False
    revoked_at_utc: str | None = None
    renewed_from_approval_id: str | None = None


_COLUMNS = [
    "approval_id",
    "engagement_id",
    "engagement_state_at_issue",
    "policy_snapshot_hash",
    "scope_lock_hash",
    "target_asset_ids_json",
    "target_asset_ids_hash",
    "canonical_hostnames_json",
    "allowed_ports_json",
    "allowed_protocols_json",
    "allowed_http_methods_json",
    "allowed_path_profile",
    "allowed_path_prefixes_json",
    "operation_profile_id",
    "tool_name",
    "tool_version",
    "tool_executable_sha256",
    "adapter_code_sha256",
    "manifest_hash",
    "egress_profile_id",
    "normalized_arguments_hash",
    "profile_params_json",
    "request_rate_budget",
    "aggregate_request_budget",
    "aggregate_byte_budget",
    "concurrency_budget",
    "aggregate_runtime_budget",
    "aggregate_model_token_budget",
    "issued_by",
    "issued_at_utc",
    "expires_at_utc",
    "approved_infrastructure_endpoints_json",
    "approved_infrastructure_endpoints_hash",
    "port_scanning_authorized",
    "intrusive_authorized",
    "lab_environment",
    "revoked_at_utc",
    "renewed_from_approval_id",
]


class ApprovalStore:
    def __init__(self, db: "Database | Path | str"):
        self._db, self._owns_db = coerce_db(db)

    def issue(self, record: ApprovalRecord) -> ApprovalRecord:
        d = asdict(record)
        d["target_asset_ids_json"] = json.dumps(record.target_asset_ids)
        d["canonical_hostnames_json"] = json.dumps(record.canonical_hostnames)
        d["allowed_ports_json"] = json.dumps(record.allowed_ports)
        d["allowed_protocols_json"] = json.dumps(record.allowed_protocols)
        d["allowed_http_methods_json"] = json.dumps(record.allowed_http_methods)
        d["allowed_path_prefixes_json"] = json.dumps(list(record.allowed_path_prefixes))
        d["approved_infrastructure_endpoints_json"] = json.dumps(
            sorted(record.approved_infrastructure_endpoints)
        )
        d["profile_params_json"] = json.dumps(
            record.profile_params or {}, sort_keys=True, separators=(",", ":")
        )
        # Auto-compute the hash if the caller didn't supply one, so
        # "approved no providers" is distinguishable from "the field
        # was never populated". Explicit values are respected (used by
        # tests that want to simulate drift).
        if not d.get("approved_infrastructure_endpoints_hash"):
            d["approved_infrastructure_endpoints_hash"] = infrastructure_endpoints_hash(
                record.approved_infrastructure_endpoints
            )
        d["port_scanning_authorized"] = 1 if record.port_scanning_authorized else 0
        d["intrusive_authorized"] = 1 if record.intrusive_authorized else 0
        d["lab_environment"] = 1 if record.lab_environment else 0
        placeholders = ",".join("?" * len(_COLUMNS))
        self._db.connection.execute(
            f"INSERT INTO approvals ({','.join(_COLUMNS)}) VALUES ({placeholders})",
            tuple(d[c] for c in _COLUMNS),
        )
        self._db.commit()
        return record

    def get(self, approval_id: str) -> ApprovalRecord | None:
        cur = self._db.connection.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        keys = [d[0] for d in cur.description]
        d = dict(zip(keys, row))
        d["target_asset_ids"] = json.loads(d.pop("target_asset_ids_json"))
        d["canonical_hostnames"] = json.loads(d.pop("canonical_hostnames_json"))
        d["allowed_ports"] = json.loads(d.pop("allowed_ports_json"))
        d["allowed_protocols"] = json.loads(d.pop("allowed_protocols_json"))
        d["allowed_http_methods"] = json.loads(d.pop("allowed_http_methods_json"))
        d["allowed_path_prefixes"] = json.loads(
            d.pop("allowed_path_prefixes_json", "[]")
        )
        d["approved_infrastructure_endpoints"] = json.loads(
            d.pop("approved_infrastructure_endpoints_json")
        )
        d["profile_params"] = json.loads(d.pop("profile_params_json", "{}"))
        d["port_scanning_authorized"] = bool(d.get("port_scanning_authorized", 0))
        d["intrusive_authorized"] = bool(d.get("intrusive_authorized", 0))
        d["lab_environment"] = bool(d.get("lab_environment", 0))
        return ApprovalRecord(**d)

    def revoke(self, approval_id: str) -> None:
        self._db.connection.execute(
            "UPDATE approvals SET revoked_at_utc = ? "
            "WHERE approval_id = ? AND revoked_at_utc IS NULL",
            (_iso(datetime.now(timezone.utc)), approval_id),
        )
        self._db.commit()

    def close(self) -> None:
        if getattr(self, "_owns_db", False):
            self._db.close()
