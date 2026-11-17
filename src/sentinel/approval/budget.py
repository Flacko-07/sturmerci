# SPDX-License-Identifier: Apache-2.0
"""Aggregate budget enforcement for approvals.

The approval carries aggregate ceilings. This module accumulates usage
and refuses operations that would exceed any ceiling. Called by
SandboxRunner before every spawn (fail closed) and after every run
(record actual usage).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from sentinel.storage.db import Database


class BudgetExhausted(Exception):
    """One or more budget dimensions is at or over its ceiling."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Usage:
    """Budget counters.

    output_bytes_used is what the operator's aggregate_byte_budget
    enforces -- bytes captured from the tool's stdout+stderr. Actual
    network bytes are not instrumented (would require packet capture
    or socket accounting at the nft boundary); treat the byte budget
    as an OUTPUT budget, not a network-transfer budget. See M6-03.

    estimated_network_probes is the adapter's declared count of probes
    (Nmap: len(ports); httpx: 1; subfinder: len(sources)). It is a
    conservative estimate, not measured -- over-counting is safe
    (budget exhausts sooner). See M6-04.
    """

    output_bytes_used: int
    estimated_network_probes: int
    runtime_used_seconds: float


def _usage_row(db: Database, approval_id: str) -> Usage:
    row = db.connection.execute(
        "SELECT output_bytes_used, estimated_network_probes, "
        "runtime_used_seconds FROM approval_usage WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    if row is None:
        return Usage(0, 0, 0.0)
    return Usage(
        row["output_bytes_used"],
        row["estimated_network_probes"],
        row["runtime_used_seconds"],
    )


def check_available(
    db: Database,
    approval_id: str,
    *,
    estimated_requests: int,
    estimated_bytes: int,
    estimated_runtime_seconds: float,
) -> None:
    """Raise BudgetExhausted if adding estimates would exceed a ceiling."""
    appr = db.connection.execute(
        "SELECT aggregate_request_budget, aggregate_byte_budget, "
        "aggregate_runtime_budget "
        "FROM approvals WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    if appr is None:
        raise BudgetExhausted(f"approval {approval_id!r} not found")
    usage = _usage_row(db, approval_id)

    if (
        usage.estimated_network_probes + estimated_requests
        > appr["aggregate_request_budget"]
    ):
        raise BudgetExhausted(
            f"request budget exhausted: "
            f"{usage.estimated_network_probes}+{estimated_requests} > "
            f"{appr['aggregate_request_budget']}"
        )
    if usage.output_bytes_used + estimated_bytes > appr["aggregate_byte_budget"]:
        raise BudgetExhausted(
            f"byte budget exhausted: "
            f"{usage.output_bytes_used}+{estimated_bytes} > "
            f"{appr['aggregate_byte_budget']}"
        )
    if (
        usage.runtime_used_seconds + estimated_runtime_seconds
        > appr["aggregate_runtime_budget"]
    ):
        raise BudgetExhausted(
            f"runtime budget exhausted: "
            f"{usage.runtime_used_seconds:.1f}+{estimated_runtime_seconds:.1f} > "
            f"{appr['aggregate_runtime_budget']}"
        )


def record_usage(
    db: Database,
    approval_id: str,
    *,
    requests: int = 0,
    bytes: int = 0,
    runtime_seconds: float = 0.0,
) -> None:
    """Atomically add the given usage to the counters."""
    now = datetime.now(timezone.utc).isoformat()
    with db.transaction_immediate() as conn:
        conn.execute(
            """INSERT INTO approval_usage
               (approval_id, output_bytes_used, estimated_network_probes,
                runtime_used_seconds, last_updated_utc)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(approval_id) DO UPDATE SET
                 output_bytes_used = output_bytes_used
                   + excluded.output_bytes_used,
                 estimated_network_probes = estimated_network_probes
                   + excluded.estimated_network_probes,
                 runtime_used_seconds = runtime_used_seconds
                   + excluded.runtime_used_seconds,
                 last_updated_utc = excluded.last_updated_utc""",
            (approval_id, bytes, requests, runtime_seconds, now),
        )


def reserve_budget(
    db: Database,
    approval_id: str,
    *,
    requests: int,
    requested_bytes: int,
    runtime_seconds: float,
) -> tuple[str, int]:
    """Atomically reserve remaining limits; returns id and byte capture cap."""
    with db.transaction_immediate() as conn:
        appr = conn.execute(
            "SELECT aggregate_request_budget, aggregate_byte_budget, "
            "aggregate_runtime_budget FROM approvals WHERE approval_id=?",
            (approval_id,),
        ).fetchone()
        if appr is None:
            raise BudgetExhausted(f"approval {approval_id!r} not found")
        used = _usage_row(db, approval_id)
        pending = conn.execute(
            "SELECT COALESCE(SUM(requests_reserved),0) requests, "
            "COALESCE(SUM(bytes_reserved),0) bytes, "
            "COALESCE(SUM(runtime_reserved_seconds),0) runtime "
            "FROM approval_budget_reservations WHERE approval_id=?",
            (approval_id,),
        ).fetchone()
        requests_left = (
            appr["aggregate_request_budget"]
            - used.estimated_network_probes
            - pending["requests"]
        )
        bytes_left = (
            appr["aggregate_byte_budget"] - used.output_bytes_used - pending["bytes"]
        )
        runtime_left = (
            appr["aggregate_runtime_budget"]
            - used.runtime_used_seconds
            - pending["runtime"]
        )
        if requests > requests_left:
            raise BudgetExhausted(
                f"request budget exhausted: {requests} > {requests_left} remaining"
            )
        if runtime_seconds > runtime_left:
            raise BudgetExhausted(
                f"runtime budget exhausted: {runtime_seconds} > {runtime_left} remaining"
            )
        capture_cap = min(requested_bytes, bytes_left)
        if capture_cap < 2:
            raise BudgetExhausted(
                "output byte budget exhausted: fewer than 2 bytes remain"
            )
        reservation_id = "bres_" + uuid4().hex[:20]
        conn.execute(
            "INSERT INTO approval_budget_reservations "
            "(reservation_id,approval_id,requests_reserved,bytes_reserved,"
            "runtime_reserved_seconds,created_at_utc) VALUES (?,?,?,?,?,?)",
            (
                reservation_id,
                approval_id,
                requests,
                capture_cap,
                runtime_seconds,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return reservation_id, capture_cap


def settle_budget(
    db: Database,
    reservation_id: str,
    *,
    actual_bytes: int,
    actual_runtime_seconds: float,
    spawned: bool,
) -> None:
    """Reconcile a reservation with captured output and observed runtime."""
    with db.transaction_immediate() as conn:
        row = conn.execute(
            "SELECT * FROM approval_budget_reservations WHERE reservation_id=?",
            (reservation_id,),
        ).fetchone()
        if row is None:
            return
        conn.execute(
            "DELETE FROM approval_budget_reservations WHERE reservation_id=?",
            (reservation_id,),
        )
        conn.execute(
            "INSERT INTO approval_usage "
            "(approval_id,output_bytes_used,estimated_network_probes,"
            "runtime_used_seconds,last_updated_utc) VALUES (?,?,?,?,?) "
            "ON CONFLICT(approval_id) DO UPDATE SET "
            "output_bytes_used=output_bytes_used+excluded.output_bytes_used, "
            "estimated_network_probes=estimated_network_probes+excluded.estimated_network_probes, "
            "runtime_used_seconds=runtime_used_seconds+excluded.runtime_used_seconds, "
            "last_updated_utc=excluded.last_updated_utc",
            (
                row["approval_id"],
                max(0, min(actual_bytes, row["bytes_reserved"])),
                row["requests_reserved"] if spawned else 0,
                max(0.0, min(actual_runtime_seconds, row["runtime_reserved_seconds"])),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
