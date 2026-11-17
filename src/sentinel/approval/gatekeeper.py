# SPDX-License-Identifier: Apache-2.0
"""Per-request gatekeeper. Gate 2 (§3.2, §5.3).

Every request re-checks policy, scope, engagement state, approval state,
tool/adapter/manifest hashes, target membership and (in a live release)
remaining budgets. No network action may proceed without a positive Decision.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .store import ApprovalStore


@dataclass(frozen=True, slots=True)
class RequestContext:
    engagement_id: str
    engagement_state: str
    policy_snapshot_hash: str
    scope_lock_hash: str
    target_asset_ids_hash: str
    target_asset_id: str
    tool_executable_sha256: str
    adapter_code_sha256: str
    manifest_hash: str
    egress_profile_id: str
    port: int
    protocol: str
    http_method: str
    path: str


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str


def check_request(
    store: ApprovalStore,
    approval_id: str,
    ctx: RequestContext,
    now: datetime | None = None,
) -> Decision:
    now = now or datetime.now(timezone.utc)

    appr = store.get(approval_id)
    if appr is None:
        return Decision(False, "approval not found")
    if appr.revoked_at_utc is not None:
        return Decision(False, "approval revoked")
    try:
        expires = datetime.fromisoformat(appr.expires_at_utc)
    except ValueError:
        return Decision(False, "approval expiry unparseable")
    if now >= expires:
        return Decision(False, "approval expired")

    if ctx.engagement_id != appr.engagement_id:
        return Decision(False, "engagement mismatch")
    if ctx.engagement_state != "active":
        return Decision(False, f"engagement state is {ctx.engagement_state!r}")

    if ctx.policy_snapshot_hash != appr.policy_snapshot_hash:
        return Decision(False, "policy hash drift")
    if ctx.scope_lock_hash != appr.scope_lock_hash:
        return Decision(False, "scope lock hash drift")
    if ctx.target_asset_ids_hash != appr.target_asset_ids_hash:
        return Decision(False, "target set drift")
    if ctx.target_asset_id not in appr.target_asset_ids:
        return Decision(False, "target asset not in approved set")

    if ctx.tool_executable_sha256 != appr.tool_executable_sha256:
        return Decision(False, "tool executable drift")
    if ctx.adapter_code_sha256 != appr.adapter_code_sha256:
        return Decision(False, "adapter code drift")
    if ctx.manifest_hash != appr.manifest_hash:
        return Decision(False, "manifest drift")
    if ctx.egress_profile_id != appr.egress_profile_id:
        return Decision(False, "egress profile drift")

    if ctx.port not in appr.allowed_ports:
        return Decision(False, f"port {ctx.port} not allowed")
    if ctx.protocol not in appr.allowed_protocols:
        return Decision(False, f"protocol {ctx.protocol!r} not allowed")
    if ctx.http_method not in appr.allowed_http_methods:
        return Decision(False, f"method {ctx.http_method!r} not allowed")

    return Decision(True, "ok")
