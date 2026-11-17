# SPDX-License-Identifier: Apache-2.0
"""Sentinel operator CLI."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import typer
from rich.console import Console
from rich.table import Table

from sentinel.storage.db import Database
from sentinel.paths import DEFAULT_DB, DEFAULT_ENGAGEMENTS_ROOT
from sentinel.engagement.store import EngagementStore
from sentinel.assets.store import AssetStore
from sentinel.approval.store import (
    ApprovalRecord, ApprovalStore, target_asset_ids_hash,
)
from sentinel.tools.manifests import ManifestStore
from sentinel.runner.sandbox_runner import (
    _current_scope_lock_hash, _current_egress_profile_id,
    _current_adapter_code_sha256,
)
from sentinel.audit.store import AuditStore


app = typer.Typer(name="sentinel", help="Sturmer local-first assessment workbench")
engagement_app = typer.Typer(help="Engagement lifecycle")
scope_app = typer.Typer(help="Scope management")
approval_app = typer.Typer(help="Approval management")
scan_app = typer.Typer(help="Scanner dispatch")
app.add_typer(engagement_app, name="engagement")
app.add_typer(scope_app, name="scope")
app.add_typer(approval_app, name="approval")
app.add_typer(scan_app, name="scan")

console = Console()


def _print_execution_status(result) -> None:
    status = getattr(result, "execution_status", None)
    if status:
        style = "green" if status == "COMPLETED" else "yellow"
        console.print(f"[{style}]Execution status:[/] {status}")


def _db() -> Database:
    return Database(DEFAULT_DB)


@app.command()
def init() -> None:
    """Create the database and run migrations."""
    db = Database(DEFAULT_DB)
    db.close()
    console.print(f"[green]Database ready:[/] {DEFAULT_DB}")
    console.print(f"[green]Engagements root:[/] {DEFAULT_ENGAGEMENTS_ROOT}")


@app.command()
def status() -> None:
    """Show database and engagement state."""
    db = _db()
    try:
        def count(table: str, where: str = "") -> int:
            return db.connection.execute(
                f"SELECT COUNT(*) FROM {table} {where}"
            ).fetchone()[0]

        engagements_total = count("engagements")
        engagements_active = count("engagements", "WHERE state = 'active'")
        approved_assets = count("approved_assets")
        now_iso = datetime.now(timezone.utc).isoformat()
        approvals_active = count(
            "approvals",
            "WHERE revoked_at_utc IS NULL AND expires_at_utc > '"
            + now_iso + "'",
        )
        manifests = count("tool_manifests")
        artifacts = count("artifacts")
        findings = count("findings")
        audits = count("audit_events")

        console.print(f"DB: {DEFAULT_DB}")
        console.print(f"Engagements: {engagements_total} "
                      f"(active: {engagements_active})")
        console.print(f"Approved assets: {approved_assets}")
        console.print(f"Active approvals: {approvals_active}")
        console.print(f"Manifests: {manifests}")
        console.print(f"Artifacts: {artifacts}")
        console.print(f"Findings: {findings}")
        console.print(f"Audit events: {audits}")
    finally:
        db.close()


# ─── engagement commands ────────────────────────────────────────────────────

@engagement_app.command("create")
def engagement_create(
    program: str = typer.Option(..., "--program", help="HackerOne program handle"),
    platform: str = typer.Option("hackerone", "--platform"),
    policy_url: str = typer.Option(None, "--policy-url"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Create a new engagement in draft state."""
    db = _db()
    try:
        eng = EngagementStore(db).create(
            platform=platform, program_name=program, policy_url=policy_url,
            actor=actor, engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
        )
        console.print(f"[green]Created[/] {eng.id} (state: {eng.state})")
        console.print(f"Next: `sentinel scope add {eng.id} --value app.example.com`")
    finally:
        db.close()


@engagement_app.command("list")
def engagement_list() -> None:
    """List engagements."""
    db = _db()
    try:
        engs = EngagementStore(db).list_all()
        table = Table("ID", "State", "Platform", "Program")
        for e in engs:
            table.add_row(e.id, e.state, e.platform, e.program_name)
        console.print(table if engs else "(no engagements)")
    finally:
        db.close()


@engagement_app.command("show")
def engagement_show(engagement_id: str = typer.Argument(...)) -> None:
    """Show one engagement."""
    db = _db()
    try:
        eng = EngagementStore(db).get(engagement_id)
        if not eng:
            console.print(f"[red]Not found[/]: {engagement_id}")
            raise typer.Exit(1)
        for k in ("id", "state", "platform", "program_name", "policy_url",
                  "created_at_utc", "closed_at_utc"):
            v = getattr(eng, k)
            if v:
                console.print(f"{k}: {v}")
    finally:
        db.close()


@engagement_app.command("activate")
def engagement_activate(
    engagement_id: str = typer.Argument(...),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Advance engagement through draft→scope_review→active."""
    db = _db()
    try:
        store = EngagementStore(db)
        eng = store.get(engagement_id)
        if not eng:
            console.print(f"[red]Not found[/]: {engagement_id}")
            raise typer.Exit(1)
        if eng.state == "draft":
            eng = store.transition(engagement_id, "scope_review", actor)
        if eng.state == "scope_review":
            eng = store.transition(engagement_id, "active", actor)
        console.print(f"[green]State:[/] {eng.state}")
    finally:
        db.close()


# ─── scope commands ─────────────────────────────────────────────────────────

@scope_app.command("add")
def scope_add(
    engagement_id: str = typer.Argument(...),
    value: str = typer.Option(..., "--value", help="hostname / IP / URL"),
    asset_type: str = typer.Option("hostname", "--type"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Add an approved asset to scope (candidate -> approved in one step)."""
    db = _db()
    try:
        astore = AssetStore(db)
        canonical = value.lower().rstrip(".")
        cid = astore.add_candidate(
            engagement_id=engagement_id, raw_value=value,
            canonical_value=canonical, asset_type=asset_type,
            discovery_source="operator",
        )
        astore.promote_candidate(cid, approved_by=actor)
        console.print(f"[green]In scope:[/] {canonical} ({asset_type})")
    finally:
        db.close()


@scope_app.command("list")
def scope_list(engagement_id: str = typer.Argument(...)) -> None:
    """List approved assets."""
    db = _db()
    try:
        rows = db.connection.execute(
            "SELECT canonical_value, asset_type, approved_by, approved_at_utc "
            "FROM approved_assets WHERE engagement_id = ? ORDER BY canonical_value",
            (engagement_id,),
        ).fetchall()
        if not rows:
            console.print("(no approved assets)")
            return
        table = Table("Value", "Type", "Approved by", "At")
        for r in rows:
            table.add_row(r["canonical_value"], r["asset_type"],
                          r["approved_by"], r["approved_at_utc"][:19])
        console.print(table)
    finally:
        db.close()


# ─── approval commands ──────────────────────────────────────────────────────

@approval_app.command("issue")
def approval_issue(
    engagement_id: str = typer.Argument(...),
    tool: str = typer.Option(..., "--tool", help="e.g. httpx, ffuf, sqlmap"),
    version: str = typer.Option(..., "--version"),
    port: list[int] = typer.Option(None, "--port",
        help="Port(s) the approval authorizes. Repeat for multiple. "
             "Required for network-capable tools."),
    method: list[str] = typer.Option(None, "--method",
        help="HTTP method(s). Repeat for multiple. Defaults to GET for "
             "network tools if omitted; refused if tool is not HTTP."),
    protocol: list[str] = typer.Option(None, "--protocol",
        help="Protocol(s) (http/https/tcp/udp). Repeat for multiple. "
             "Required for network tools."),
    profile: str = typer.Option(None, "--profile",
        help="Operation profile. Defaults to manifest.allowed_profiles[0]."),
    provider: list[str] = typer.Option(None, "--provider",
        help="Infrastructure provider(s) to authorize (e.g. crt.sh). "
             "Repeat for multiple. NOT auto-populated from the manifest: "
             "the operator must explicitly authorize each provider."),
    profile_param: list[str] = typer.Option(None, "--profile-param",
        help="Profile parameter KEY=VALUE. Repeat for each. When provided, "
             "the approval binds these exact values: any run whose "
             "profile_params differ for these keys is refused. Use this "
             "to pre-commit to a specific wordlist / template set / "
             "technique. Empty = no param binding (backwards-compatible)."),
    path_profile: str = typer.Option("default", "--path-profile",
        help="default | restricted. 'restricted' requires --path-prefix "
             "and a proxy-enabled adapter run."),
    path_prefix: list[str] = typer.Option(None, "--path-prefix",
        help="Allowed URL path prefix(es) when --path-profile=restricted."),
    policy_snapshot: str = typer.Option("", "--policy-snapshot",
        help="policy_snapshots.policy_hash for this engagement. Empty "
             "means the approval is not policy-bound (warning issued)."),
    intrusive: bool = typer.Option(False, "--intrusive",
        help="Authorize Class 3 intrusive operations. Requires --yes "
             "or interactive confirmation."),
    lab: bool = typer.Option(False, "--lab",
        help="Mark approval as lab-only (required for metasploit/exploit)."),
    port_scanning_authorized: bool = typer.Option(False,
        "--port-scanning-authorized",
        help="Authorize Nmap port scanning against resolved IPs. "
             "Required for the nmap adapter. Independent of --intrusive."),
    duration_min: int = typer.Option(30, "--duration-min"),
    rate: int = typer.Option(10, "--rate", help="max requests per second"),
    budget: int = typer.Option(1000, "--budget", help="max total requests"),
    yes: bool = typer.Option(False, "--yes", "-y",
        help="Skip interactive confirmation for --intrusive."),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Issue an approval bound to current scope + manifest.

    Explicit authorization only: --port, --method, --protocol and
    --provider are NEVER auto-derived from the manifest. The manifest
    declares what the tool MAY contact; the approval declares what the
    operator AUTHORIZES for this engagement.
    """
    db = _db()
    try:
        eng = EngagementStore(db).get(engagement_id)
        if not eng or eng.state != "active":
            console.print(f"[red]Engagement must be active[/] "
                          f"(current: {eng.state if eng else 'missing'})")
            raise typer.Exit(1)

        manifest = ManifestStore(db).get_by_tool_version(tool, version)
        if not manifest:
            console.print(f"[red]No manifest[/] for {tool} {version}")
            console.print("Register the manifest first "
                          "(see docs/operator-guide.md)")
            raise typer.Exit(1)

        astore = AssetStore(db)
        target_ids = astore.approved_ids(engagement_id)
        if not target_ids:
            console.print("[red]No approved assets[/]; add scope first")
            raise typer.Exit(1)

        hostnames = [r[0] for r in db.connection.execute(
            "SELECT canonical_value FROM approved_assets "
            "WHERE engagement_id = ? AND asset_type = 'hostname'",
            (engagement_id,),
        ).fetchall()]

        # --- Lab flag sanity ---
        if lab and eng.platform != "lab":
            console.print(
                f"[red]--lab requires engagement.platform='lab'[/] "
                f"(current: {eng.platform!r}). See "
                f"docs/ecr-v1.0.2-class3-amendment.md §4."
            )
            raise typer.Exit(1)

        # --- Intrusive confirmation ---
        if intrusive:
            if not yes:
                msg = (
                    "Authorize intrusive Class 3 operations for this "
                    "engagement? This can break the target and is "
                    "lab-only where the runner requires it."
                )
                if not typer.confirm(msg, default=False):
                    console.print("[yellow]Aborted by operator.[/]")
                    raise typer.Exit(1)
            console.print(
                "[yellow]WARNING:[/] --intrusive authorizes Class 3 "
                "tools. Runner still requires lab_environment for "
                "high-risk tools (metasploit)."
            )

        # --- Network capability: explicit ports/methods/protocols ---
        network_capable = bool(manifest.manifest.network_access)
        if network_capable:
            if not port:
                console.print(
                    "[red]Network-capable tool requires --port[/] "
                    f"({tool} {version}). Examples: --port 443, "
                    "--port 80 --port 8080."
                )
                raise typer.Exit(1)
            if not protocol:
                console.print(
                    "[red]Network-capable tool requires --protocol[/] "
                    f"({tool} {version}). Examples: --protocol https, "
                    "--protocol http."
                )
                raise typer.Exit(1)
            if not method:
                console.print(
                    "[yellow]Note:[/] no --method given for network "
                    "tool; defaulting to GET only. Pass --method to "
                    "authorize POST/PUT/etc."
                )
                method = ["GET"]

        # --- Provider: subset-of-manifest, or empty ---
        declared_providers = set(manifest.manifest.infrastructure_endpoints)
        selected_providers = list(provider or [])
        if selected_providers:
            bad = set(selected_providers) - declared_providers
            if bad:
                console.print(
                    f"[red]--provider {sorted(bad)} not declared by "
                    f"manifest[/] (declared: "
                    f"{sorted(declared_providers) or '[]'})"
                )
                raise typer.Exit(1)
        elif declared_providers:
            console.print(
                f"[yellow]Note:[/] {tool} declares providers "
                f"{sorted(declared_providers)} but none were authorized. "
                f"The adapter will refuse at run time unless "
                f"--provider is passed. This is intentional: the "
                f"operator authorizes providers explicitly."
            )

        # --- Path profile sanity ---
        if path_profile not in ("default", "restricted"):
            console.print(
                f"[red]--path-profile must be 'default' or 'restricted'[/] "
                f"(got {path_profile!r})"
            )
            raise typer.Exit(1)
        if path_profile == "restricted":
            if not path_prefix:
                console.print(
                    "[red]--path-profile=restricted requires "
                    "--path-prefix[/]"
                )
                raise typer.Exit(1)

        # --- Policy snapshot: verify against DB if provided ---
        if policy_snapshot:
            row = db.connection.execute(
                "SELECT 1 FROM policy_snapshots "
                "WHERE engagement_id = ? AND policy_hash = ?",
                (engagement_id, policy_snapshot),
            ).fetchone()
            if not row:
                console.print(
                    f"[red]--policy-snapshot {policy_snapshot!r} does "
                    f"not match any policy_snapshots row for this "
                    f"engagement[/]"
                )
                raise typer.Exit(1)
        elif eng.platform == "lab":
            # Lab engagements may issue unbound approvals — useful for
            # developing adapter flows before a real program is in scope.
            console.print(
                "[yellow]Note:[/] no --policy-snapshot; lab engagement "
                "approval will not be policy-bound. Runner still enforces "
                "scope and target set."
            )
        else:
            # (batch A) External engagements MUST bind to a policy
            # snapshot. The reviewer's finding: a HackerOne approval
            # without a policy snapshot has no way to prove the operator
            # actually read the program policy at issue time.
            console.print(
                f"[red]--policy-snapshot required for non-lab engagements[/] "
                f"(platform={eng.platform!r}). Upload the policy snapshot "
                f"first, then pass its hash here. Lab engagements are the "
                f"only ones that may issue unbound approvals."
            )
            raise typer.Exit(1)

        scope_hash = _current_scope_lock_hash(db, engagement_id, "")
        egress_id = _current_egress_profile_id()

        adapter_path = Path(f"src/sentinel/adapters/{tool}.py")
        if not adapter_path.exists():
            adapter_path = Path("src/sentinel/runner/sandbox_runner.py")
        adapter_hash = _current_adapter_code_sha256(adapter_path)

        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=duration_min)

        if profile:
            if profile not in manifest.manifest.allowed_profiles \
                    and profile.split("/")[-1] not in manifest.manifest.allowed_profiles:
                console.print(
                    f"[red]--profile {profile!r} not in "
                    f"manifest.allowed_profiles[/] "
                    f"({sorted(manifest.manifest.allowed_profiles)})"
                )
                raise typer.Exit(1)
            profile_id = profile
        else:
            profile_id = (
                manifest.manifest.allowed_profiles[0]
                if manifest.manifest.allowed_profiles else "inventory"
            )

        # (6A) Parse --profile-param KEY=VALUE into a dict and hash it.
        from sentinel.runner.profiles import params_hash
        bound_params: dict[str, str] = {}
        for raw in (profile_param or []):
            if "=" not in raw:
                console.print(
                    f"[red]--profile-param must be KEY=VALUE[/] "
                    f"(got {raw!r})"
                )
                raise typer.Exit(1)
            k, v = raw.split("=", 1)
            if not k:
                console.print(
                    f"[red]--profile-param key is empty[/] (got {raw!r})"
                )
                raise typer.Exit(1)
            bound_params[k] = v
        from sentinel.runner.profiles import get_profile, ProfileError
        try:
            selected_profile = get_profile(profile_id)
        except ProfileError:
            selected_profile = None
        requires_param_binding = bool(
            selected_profile and selected_profile.requires_param_binding
        )
        if requires_param_binding:
            missing_binding = selected_profile.param_binding_keys - set(bound_params)
            if missing_binding:
                console.print(
                    "[red]Class 3 profile requires --profile-param for: "
                    f"{', '.join(sorted(missing_binding))}[/]"
                )
                raise typer.Exit(1)
            bound_params = {
                key: bound_params[key]
                for key in selected_profile.param_binding_keys
            }
        args_hash = (
            params_hash(bound_params)
            if bound_params or requires_param_binding else ""
        )
        approval_profile_params = (
            {key: "" for key in selected_profile.param_binding_keys}
            if requires_param_binding else bound_params
        )

        appr = ApprovalRecord(
            approval_id="appr_" + uuid4().hex[:16],
            engagement_id=engagement_id,
            engagement_state_at_issue=eng.state,
            policy_snapshot_hash=policy_snapshot,
            scope_lock_hash=scope_hash,
            target_asset_ids=target_ids,
            target_asset_ids_hash=target_asset_ids_hash(target_ids),
            canonical_hostnames=hostnames,
            allowed_ports=list(port or []),
            allowed_protocols=list(protocol or []),
            allowed_http_methods=list(method or []),
            allowed_path_profile=path_profile,
            operation_profile_id=profile_id,
            tool_name=tool, tool_version=version,
            tool_executable_sha256=manifest.manifest.executable_sha256,
            adapter_code_sha256=adapter_hash,
            manifest_hash=manifest.manifest_hash,
            egress_profile_id=egress_id,
            normalized_arguments_hash=args_hash,
            profile_params=approval_profile_params,
            request_rate_budget=rate,
            aggregate_request_budget=budget,
            aggregate_byte_budget=10_000_000,
            concurrency_budget=1,
            aggregate_runtime_budget=duration_min * 60,
            aggregate_model_token_budget=100_000,
            issued_by=actor,
            issued_at_utc=now.isoformat(),
            expires_at_utc=expires.isoformat(),
            approved_infrastructure_endpoints=selected_providers,
            allowed_path_prefixes=list(path_prefix or []),
            intrusive_authorized=intrusive,
            lab_environment=lab,
            port_scanning_authorized=port_scanning_authorized,
        )
        ApprovalStore(db).issue(appr)
        console.print(f"[green]Approval[/] {appr.approval_id}")
        console.print(f"Tool: {tool} {version} (profile: {profile_id})")
        console.print(f"Hostnames: {', '.join(hostnames) or '(none)'}")
        console.print(f"Ports: {appr.allowed_ports}")
        console.print(f"Protocols: {appr.allowed_protocols}")
        console.print(f"Methods: {appr.allowed_http_methods}")
        if selected_providers:
            console.print(f"Providers: {selected_providers}")
        else:
            console.print("Providers: (none)")
        console.print(
            f"Path profile: {path_profile}"
            + (f" prefixes={path_prefix}" if path_prefix else "")
        )
        if bound_params and requires_param_binding:
            console.print(
                f"Bound param keys: {sorted(bound_params)} "
                f"(values committed by hash {args_hash[:16]}…; not stored)"
            )
        elif bound_params:
            console.print(f"Bound params: {bound_params}")
        elif requires_param_binding:
            console.print("Bound params: {} (empty parameter set bound)")
        else:
            console.print("Bound params: (none)")
        console.print(
            f"Intrusive: {intrusive}  Lab: {lab}  "
            f"Port-scanning: {port_scanning_authorized}"
        )
        console.print(f"Expires: {appr.expires_at_utc}")
    finally:
        db.close()

@approval_app.command("list")
def approval_list(engagement_id: str = typer.Argument(...)) -> None:
    """List approvals for an engagement."""
    db = _db()
    try:
        rows = db.connection.execute(
            "SELECT approval_id, tool_name, tool_version, issued_at_utc, "
            "expires_at_utc, revoked_at_utc FROM approvals "
            "WHERE engagement_id = ? ORDER BY issued_at_utc DESC",
            (engagement_id,),
        ).fetchall()
        if not rows:
            console.print("(no approvals)")
            return
        table = Table("ID", "Tool", "Version", "Expires", "Revoked")
        for r in rows:
            table.add_row(
                r["approval_id"], r["tool_name"], r["tool_version"],
                r["expires_at_utc"][:19],
                r["revoked_at_utc"][:19] if r["revoked_at_utc"] else "",
            )
        console.print(table)
    finally:
        db.close()


@approval_app.command("revoke")
def approval_revoke(
    approval_id: str = typer.Argument(...),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Revoke an approval."""
    db = _db()
    try:
        row = db.connection.execute(
            "SELECT engagement_id FROM approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if not row:
            console.print(f"[red]Not found[/]: {approval_id}")
            raise typer.Exit(1)
        ApprovalStore(db).revoke(approval_id)
        AuditStore(db).append(
            engagement_id=row["engagement_id"], actor=actor,
            event_type="approval_revoked_cli", decision="revoked",
            details={"approval_id": approval_id},
        )
        console.print(f"[green]Revoked[/] {approval_id}")
    finally:
        db.close()


# ─── scan commands ──────────────────────────────────────────────────────────

@scan_app.command("gitleaks")
def scan_gitleaks(
    engagement_id: str = typer.Argument(...),
    subdir: str = typer.Option("source", "--subdir"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run Gitleaks against engagement/<subdir>/."""
    from sentinel.adapters.gitleaks import run_gitleaks
    db = _db()
    try:
        result = run_gitleaks(
            db=db, engagement_id=engagement_id,
            engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
            scan_subdir=subdir, actor=actor,
        )
        _print_execution_status(result)
        console.print(f"Findings: {result.findings_count}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("httpx")
def scan_httpx(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target"),
    port: int = typer.Option(443, "--port"),
    scheme: str = typer.Option("https", "--scheme"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run httpx inventory against an approved target."""
    from sentinel.adapters.httpx import run_httpx
    db = _db()
    try:
        result = run_httpx(
            db=db, engagement_id=engagement_id,
            approval_id=approval_id,
            target_hostname=target, port=port, scheme=scheme,
            method="GET",
            engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
            actor=actor,
        )
        _print_execution_status(result)
        console.print(f"Endpoints written: {result.endpoints_written}")
        console.print(f"Evidence: {result.sandbox.audit_event_seq}")
    finally:
        db.close()


@scan_app.command("subfinder")
def scan_subfinder(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    domain: str = typer.Option(..., "--domain"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run Subfinder (crt.sh only) for passive subdomain discovery."""
    from sentinel.adapters.subfinder import run_subfinder
    db = _db()
    try:
        result = run_subfinder(
            db=db, engagement_id=engagement_id,
            approval_id=approval_id, target_domain=domain,
            engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
            actor=actor,
        )
        _print_execution_status(result)
        console.print(f"Candidates written: {result.candidates_written}")
        console.print(f"Skipped (invalid): {result.candidates_skipped_invalid}")
        console.print(f"Skipped (dup): {result.candidates_skipped_duplicate}")
    finally:
        db.close()


@scan_app.command("nmap")
def scan_nmap(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target"),
    ports: str = typer.Option(..., "--ports", help="comma-separated, e.g. 80,443"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run Nmap TCP connect scan against an approved target."""
    from sentinel.adapters.nmap import run_nmap
    db = _db()
    try:
        port_list = [int(p) for p in ports.split(",") if p.strip()]
        result = run_nmap(
            db=db, engagement_id=engagement_id,
            approval_id=approval_id, target_hostname=target,
            ports=port_list,
            engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
            actor=actor,
        )
        _print_execution_status(result)
        console.print(f"Open ports written: {result.open_ports_written}")
    finally:
        db.close()


triage_app = typer.Typer(help="Triage and findings")
report_app = typer.Typer(help="Report generation")
app.add_typer(triage_app, name="triage")
app.add_typer(report_app, name="report")


# ─── triage commands ────────────────────────────────────────────────────────

@triage_app.command("run")
def triage_run(
    engagement_id: str = typer.Argument(...),
    artifact: str = typer.Option(..., "--artifact", help="Evidence ID (ev_...)"),
    model: str = typer.Option("qwen3:1.7b", "--model"),
    actor: str = typer.Option("operator", "--actor"),
    use_fewshot: bool = typer.Option(False, "--fewshot/--no-fewshot"),
) -> None:
    """Triage a sanitized artifact into a candidate finding."""
    from sentinel.triage.pipeline import triage_artifact, TriageError
    db = _db()
    try:
        try:
            result = triage_artifact(
                db=db, engagement_id=engagement_id,
                artifact_id=artifact, actor=actor, model=model,
                use_fewshot=use_fewshot,
            )
        except TriageError as e:
            console.print(f"[red]Triage failed:[/] {e}")
            raise typer.Exit(1)
        console.print(f"[green]Finding created:[/] {result.finding_id}")
        console.print(f"Category: {result.output.candidate_category}")
        console.print(f"Confidence: {result.output.confidence_hint}")
        console.print(f"KB hits: {len(result.kb_hits)}")
        if result.dropped_evidence:
            console.print(f"[yellow]Dropped evidence IDs:[/] {result.dropped_evidence}")
        if result.dropped_references:
            console.print(f"[yellow]Dropped references:[/] {result.dropped_references}")
        if result.examples_used:
            console.print(f"Few-shot examples: {len(result.examples_used)}")
    finally:
        db.close()


# ─── findings commands ──────────────────────────────────────────────────────

@triage_app.command("findings")
def findings_list(engagement_id: str = typer.Argument(...)) -> None:
    """List findings for an engagement."""
    db = _db()
    try:
        rows = db.connection.execute(
            "SELECT id, lifecycle_state, candidate_category, confidence_hint, "
            "title, created_at_utc FROM findings WHERE engagement_id = ? "
            "ORDER BY created_at_utc DESC",
            (engagement_id,),
        ).fetchall()
        if not rows:
            console.print("(no findings)")
            return
        table = Table("ID", "State", "Category", "Confidence", "Title")
        for r in rows:
            title = (r["title"] or "")[:40]
            table.add_row(
                r["id"], r["lifecycle_state"], r["candidate_category"],
                r["confidence_hint"], title,
            )
        console.print(table)
    finally:
        db.close()


@triage_app.command("show")
def finding_show(finding_id: str = typer.Argument(...)) -> None:
    """Show full detail of one finding."""
    db = _db()
    try:
        row = db.connection.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,),
        ).fetchone()
        if not row:
            console.print(f"[red]Not found[/]: {finding_id}")
            raise typer.Exit(1)
        import json
        console.print(f"[bold]ID:[/] {row['id']}")
        console.print(f"[bold]State:[/] {row['lifecycle_state']}")
        console.print(f"[bold]Category:[/] {row['candidate_category']}")
        console.print(f"[bold]Confidence:[/] {row['confidence_hint']}")
        console.print(f"[bold]Summary:[/] {row['summary']}")
        console.print(f"[bold]Recommended next step:[/] {row['recommended_next_step']}")
        refs = json.loads(row["possible_references_json"] or "[]")
        if refs:
            console.print(f"[bold]References:[/] {', '.join(refs)}")
        provenance = db.connection.execute(
            "SELECT original_identifier, reference_type, validation_status, "
            "validation_source, lookup_outcome, rejection_reason "
            "FROM finding_reference_provenance WHERE finding_id=? "
            "ORDER BY original_identifier",
            (finding_id,),
        ).fetchall()
        if provenance:
            table = Table(
                "Proposed reference", "Type", "Status", "Source", "Outcome", "Reason",
            )
            for ref in provenance:
                table.add_row(
                    ref["original_identifier"], ref["reference_type"],
                    ref["validation_status"], ref["validation_source"],
                    ref["lookup_outcome"], ref["rejection_reason"] or "",
                )
            console.print(table)
        missing = json.loads(row["missing_evidence_json"] or "[]")
        if missing:
            console.print("[bold]Missing evidence:[/]")
            for m in missing:
                console.print(f"  • {m}")
        ev_rows = db.connection.execute(
            "SELECT evidence_id FROM finding_evidence WHERE finding_id = ?",
            (finding_id,),
        ).fetchall()
        if ev_rows:
            console.print(f"[bold]Evidence:[/] "
                          f"{', '.join(r['evidence_id'] for r in ev_rows)}")
    finally:
        db.close()


@triage_app.command("transition")
def finding_transition(
    finding_id: str = typer.Argument(...),
    to_state: str = typer.Argument(...),
    actor: str = typer.Option("operator", "--actor"),
    note: str = typer.Option("", "--note"),
) -> None:
    """Advance a finding's lifecycle state. Valid states: needs_evidence,
    ready_for_review, human_validated, report_ready, submitted, resolved,
    duplicate, rejected."""
    from sentinel.findings import FindingStore, FindingError
    db = _db()
    try:
        try:
            row = FindingStore(db).transition(
                finding_id, to_state, actor=actor, note=note,
            )
        except FindingError as e:
            console.print(f"[red]Transition refused:[/] {e}")
            raise typer.Exit(1)
        console.print(f"[green]State:[/] {row['lifecycle_state']}")
    finally:
        db.close()


# ─── report commands ────────────────────────────────────────────────────────

@report_app.command("generate")
def report_generate(
    engagement_id: str = typer.Argument(...),
    output: Path = typer.Option(
        Path("report.md"), "--output", "-o",
        help="Output Markdown file",
    ),
    include_candidate: bool = typer.Option(
        False, "--include-candidate/--validated-only",
        help="Include candidate findings in the report",
    ),
) -> None:
    """Generate a Markdown report for the engagement."""
    from sentinel.reporting.report import generate_report, ReportError
    db = _db()
    try:
        try:
            report = generate_report(
                db, engagement_id=engagement_id,
                include_candidate=include_candidate,
            )
        except ReportError as e:
            console.print(f"[red]Report failed:[/] {e}")
            raise typer.Exit(1)
        output.write_text(report, encoding="utf-8")
        console.print(f"[green]Report written:[/] {output}")
        console.print(f"Size: {len(report)} chars")
    finally:
        db.close()


@scan_app.command("bandit")
def scan_bandit(
    engagement_id: str = typer.Argument(...),
    subdir: str = typer.Option("source", "--subdir"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run Bandit (Python static analysis) against engagement/<subdir>/."""
    from sentinel.adapters.bandit import run_bandit
    db = _db()
    try:
        result = run_bandit(
            db=db, engagement_id=engagement_id,
            engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
            scan_subdir=subdir, actor=actor,
        )
        console.print(f"[green]Scan complete[/]")
        _print_execution_status(result)
        console.print(f"Findings: {result.findings_count}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("dig")
def scan_dig(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="domain to look up"),
    resolver: str = typer.Option(..., "--resolver", help="resolver IP (must be authorized)"),
    record_type: str = typer.Option("A", "--type"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run dig against an approved resolver (Class 1)."""
    from sentinel.adapters.dig import run_dig, DigAdapterError
    db = _db()
    try:
        try:
            result = run_dig(
                db=db, engagement_id=engagement_id,
                approval_id=approval_id,
                target_domain=target, resolver_ip=resolver,
                record_type=record_type,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                actor=actor,
            )
        except DigAdapterError as e:
            console.print(f"[red]dig refused:[/] {e}")
            raise typer.Exit(1)
        console.print(f"[green]Records found:[/] {len(result.records)}")
        _print_execution_status(result)
        for r in result.records[:10]:
            console.print(f"  {r.name} {r.ttl} {r.record_class} {r.record_type} {r.value}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("ffuf")
def scan_ffuf(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="hostname"),
    port: int = typer.Option(443, "--port"),
    scheme: str = typer.Option("https", "--scheme"),
    wordlist: str = typer.Option("common.txt", "--wordlist",
        help="filename under the packaged wordlists/ resource"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run ffuf directory discovery against an approved target (Class 2)."""
    from sentinel.adapters.ffuf import run_ffuf, FfufAdapterError
    db = _db()
    try:
        try:
            result = run_ffuf(
                db=db, engagement_id=engagement_id,
                approval_id=approval_id,
                target_hostname=target, port=port, scheme=scheme,
                wordlist_name=wordlist,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                actor=actor,
            )
        except FfufAdapterError as e:
            console.print(f"[red]ffuf refused:[/] {e}")
            raise typer.Exit(1)
        console.print(f"[green]Wordlist:[/] {result.wordlist_size} paths")
        _print_execution_status(result)
        console.print(f"[green]Findings:[/] {result.findings_count}")
        console.print(f"Blocked paths skipped: {result.blocked_paths_skipped}")
        for f in result.findings[:10]:
            console.print(f"  [{f.status}] {f.path} ({f.length}B, {f.content_type})")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("semgrep")
def scan_semgrep(
    engagement_id: str = typer.Argument(...),
    subdir: str = typer.Option("source", "--subdir"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run Semgrep (source static analysis) against engagement/<subdir>/."""
    from sentinel.adapters.semgrep import run_semgrep, SemgrepAdapterError
    db = _db()
    try:
        try:
            result = run_semgrep(
                db=db, engagement_id=engagement_id,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                scan_subdir=subdir, actor=actor,
            )
        except SemgrepAdapterError as e:
            console.print(f"[red]semgrep refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        console.print(f"[green]Findings:[/] {result.findings_count}")
        for f in result.findings[:10]:
            console.print(f"  {f.rule_id} {f.path}:{f.line}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()

@scan_app.command("trivy")
def scan_trivy(
    engagement_id: str = typer.Argument(...),
    subdir: str = typer.Option("source", "--subdir"),
    scan_type: str = typer.Option("fs", "--scan-type"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run Trivy (dependency scan, offline) against engagement/<subdir>/."""
    from sentinel.adapters.trivy import run_trivy, TrivyAdapterError
    db = _db()
    try:
        try:
            result = run_trivy(
                db=db, engagement_id=engagement_id,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                scan_subdir=subdir, scan_type=scan_type, actor=actor,
            )
        except TrivyAdapterError as e:
            console.print(f"[red]trivy refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        console.print(f"[green]Findings:[/] {result.findings_count}")
        for f in result.findings[:10]:
            console.print(f"  {f.vuln_id} {f.package}:{f.installed_version} -> {f.fixed_version}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()

@scan_app.command("whois")
def scan_whois(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="domain to look up"),
    server: str = typer.Option("", "--server",
        help="WHOIS server (empty = derive from TLD)"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run whois against an approved server (Class 1)."""
    from sentinel.adapters.whois import run_whois, WhoisAdapterError
    db = _db()
    try:
        try:
            result = run_whois(
                db=db, engagement_id=engagement_id, approval_id=approval_id,
                target_domain=target,
                whois_server=server or None,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT, actor=actor,
            )
        except WhoisAdapterError as e:
            console.print(f"[red]whois refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        console.print(f"[green]Evidence:[/] {result.evidence.evidence_id}")
    finally:
        db.close()

@scan_app.command("nikto")
def scan_nikto(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="hostname"),
    port: int = typer.Option(443, "--port"),
    scheme: str = typer.Option("https", "--scheme"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run nikto web server scan against an approved target (Class 2)."""
    from sentinel.adapters.nikto import run_nikto, NiktoAdapterError
    db = _db()
    try:
        try:
            result = run_nikto(
                db=db, engagement_id=engagement_id,
                approval_id=approval_id,
                target_hostname=target, port=port, scheme=scheme,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                actor=actor,
            )
        except NiktoAdapterError as e:
            console.print(f"[red]nikto refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        if result.banner:
            console.print(f"[green]Banner:[/] {result.banner}")
        console.print(f"[green]Findings:[/] {result.findings_count}")
        for f in result.findings[:10]:
            console.print(f"  [{f.item_id}] {f.method} {f.url} — {f.msg[:80]}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("scion")
def scan_scion(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="domain to discover"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run scion passive subdomain discovery (Class 1)."""
    from sentinel.adapters.scion import run_scion, ScionAdapterError
    db = _db()
    try:
        try:
            result = run_scion(
                db=db, engagement_id=engagement_id,
                approval_id=approval_id,
                target_domain=target,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                actor=actor,
            )
        except ScionAdapterError as e:
            console.print(f"[red]scion refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        console.print(f"[green]Hosts found:[/] {result.findings_count}")
        for f in result.findings[:15]:
            console.print(f"  {f.hostname}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("sqlmap")
def scan_sqlmap(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="hostname"),
    port: int = typer.Option(80, "--port"),
    scheme: str = typer.Option("http", "--scheme"),
    path: str = typer.Option("/", "--path"),
    query: str = typer.Option("", "--query",
        help="URL query string for GET, e.g. 'id=1'"),
    data: str = typer.Option("", "--data",
        help="POST body, e.g. 'id=1'. Empty means GET."),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run sqlmap detection (Class 3, LAB-ONLY). Requires intrusive_authorized=True."""
    from sentinel.adapters.sqlmap import run_sqlmap, SqlmapAdapterError
    db = _db()
    try:
        try:
            result = run_sqlmap(
                db=db, engagement_id=engagement_id, approval_id=approval_id,
                target_hostname=target, port=port, scheme=scheme,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                path=path, query=query, data=data or None,
                actor=actor,
            )
        except SqlmapAdapterError as e:
            console.print(f"[red]sqlmap refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        console.print(f"[green]Findings:[/] {result.findings_count}")
        for f in result.findings[:10]:
            console.print(f"  {f.method} {f.parameter}: {f.technique}")
        console.print(f"Log bytes: {result.log_bytes}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("nuclei")
def scan_nuclei(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="hostname"),
    port: int = typer.Option(443, "--port"),
    scheme: str = typer.Option("https", "--scheme"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run nuclei template scan against an approved target (Class 2)."""
    from sentinel.adapters.nuclei import run_nuclei, NucleiAdapterError
    db = _db()
    try:
        try:
            result = run_nuclei(
                db=db, engagement_id=engagement_id, approval_id=approval_id,
                target_hostname=target, port=port, scheme=scheme,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT, actor=actor,
            )
        except NucleiAdapterError as e:
            console.print(f"[red]nuclei refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        console.print(f"[green]Findings:[/] {result.findings_count}")
        for f in result.findings[:10]:
            console.print(f"  [{f.severity}] {f.template_id} {f.matched_at}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("metasploit")
def scan_metasploit(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="hostname"),
    port: int = typer.Option(80, "--port"),
    scheme: str = typer.Option("http", "--scheme"),
    module: str = typer.Option(..., "--module",
        help="e.g. auxiliary/scanner/http/title"),
    mode: str = typer.Option("check", "--mode",
        help="check (Class 2) or exploit (Class 3, LAB-ONLY)"),
    payload: str = typer.Option("", "--payload",
        help="payload module for exploit mode, e.g. cmd/unix/generic"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run Metasploit check (Class 2) or exploit (Class 3, LAB-ONLY)."""
    from sentinel.adapters.metasploit import (
        run_metasploit_check, run_metasploit_exploit,
        MetasploitAdapterError,
    )
    if mode not in ("check", "exploit"):
        console.print(f"[red]invalid --mode {mode!r}; use check or exploit[/]")
        raise typer.Exit(1)
    db = _db()
    try:
        try:
            if mode == "exploit":
                result = run_metasploit_exploit(
                    db=db, engagement_id=engagement_id,
                    approval_id=approval_id,
                    target_hostname=target, port=port, scheme=scheme,
                    module=module,
                    engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                    payload=payload or None, actor=actor,
                )
            else:
                result = run_metasploit_check(
                    db=db, engagement_id=engagement_id,
                    approval_id=approval_id,
                    target_hostname=target, port=port, scheme=scheme,
                    module=module,
                    engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                    actor=actor,
                )
        except MetasploitAdapterError as e:
            console.print(f"[red]metasploit refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        console.print(f"[green]Profile:[/] {result.profile}")
        console.print(f"[green]Findings:[/] {result.findings_count}")
        for f in result.findings[:10]:
            console.print(f"  [{f.kind}] {f.host_port} {f.field}: {f.value[:80]}")
        console.print(f"Spool bytes: {result.spool_bytes}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


# (batch-7) Wire the tool-manifest management sub-app. The db_factory
# is passed in rather than imported to avoid a circular import.
from sentinel.tools.cli import register_tool_cli as _register_tool_cli
# Pass a lambda so tests that monkeypatch `sentinel.cli._db`
# take effect — a direct `_db` reference would bind at import time.
_register_tool_cli(app, lambda: _db())


@scan_app.command("exiftool")
def scan_exiftool(
    engagement_id: str = typer.Argument(...),
    subdir: str = typer.Option("source", "--subdir",
        help="Directory under engagement/<eng_id>/ to scan. "
             "Default: source."),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run ExifTool (document metadata extraction) against engagement/<subdir>/. (Class 0)"""
    from sentinel.adapters.exiftool import (
        run_exiftool, ExifToolAdapterError,
    )
    db = _db()
    try:
        try:
            result = run_exiftool(
                db, engagement_id=engagement_id,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                scan_subdir=subdir, actor=actor,
            )
        except ExifToolAdapterError as e:
            console.print(f"[red]exiftool refused:[/] {e}")
            raise typer.Exit(1)
        console.print(f"[green]Files scanned:[/] {result.files_scanned}")
        _print_execution_status(result)
        console.print(f"[green]Files with sensitive metadata:[/] {result.findings_count}")
        for f in result.findings[:10]:
            fields = ", ".join(f.sensitive_fields[:5])
            if len(f.sensitive_fields) > 5:
                fields += f", +{len(f.sensitive_fields) - 5} more"
            console.print(f"  {f.file_path} ({f.file_type}) -> {fields}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("zap")
def scan_zap(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="hostname"),
    port: int = typer.Option(443, "--port"),
    scheme: str = typer.Option("https", "--scheme"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run ZAP baseline (spider + passive) scan against an approved target (Class 2)."""
    from sentinel.adapters.zap import run_zap_baseline, ZapAdapterError
    db = _db()
    try:
        try:
            result = run_zap_baseline(
                db=db, engagement_id=engagement_id,
                approval_id=approval_id,
                target_hostname=target, port=port, scheme=scheme,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT, actor=actor,
            )
        except ZapAdapterError as e:
            console.print(f"[red]zap refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        console.print(f"[green]Findings:[/] {result.findings_count}")
        for f in result.findings[:15]:
            console.print(
                f"  [{f.risk}] {f.name} ({f.instance_count} instance(s))"
            )
        console.print(f"Report bytes: {result.report_bytes}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


@scan_app.command("theharvester")
def scan_theharvester(
    engagement_id: str = typer.Argument(...),
    approval_id: str = typer.Option(..., "--approval"),
    target: str = typer.Option(..., "--target", help="domain to discover"),
    providers: str = typer.Option(
        "crtsh,otx,rapiddns", "--providers",
        help="comma-separated; subset of crtsh,otx,rapiddns",
    ),
    limit: int = typer.Option(500, "--limit"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Run theHarvester passive discovery against an approved domain (Class 1)."""
    from sentinel.adapters.theharvester import (
        run_theharvester, TheHarvesterAdapterError,
    )
    prov = tuple(s.strip() for s in providers.split(",") if s.strip())
    db = _db()
    try:
        try:
            result = run_theharvester(
                db=db, engagement_id=engagement_id,
                approval_id=approval_id,
                target_domain=target,
                engagements_root=DEFAULT_ENGAGEMENTS_ROOT,
                providers=prov,
                limit=limit, actor=actor,
            )
        except TheHarvesterAdapterError as e:
            console.print(f"[red]theHarvester refused:[/] {e}")
            raise typer.Exit(1)
        _print_execution_status(result)
        console.print(f"[green]Providers:[/] {','.join(result.providers_used)}")
        console.print(f"[green]Hosts found:[/] {result.findings_count}")
        for f in result.findings[:15]:
            console.print(f"  {f.hostname}")
        console.print(f"Evidence: {result.evidence.evidence_id}")
    finally:
        db.close()


# (v3-follow-up, Bug 3) Operator-facing evidence management.
# Prior fix added a Python function release_held_artifact(); this exposes
# it as a CLI without exposing the module-path-vs-store confusion that
# tripped three attempted invocations during the end-to-end run.

evidence_app = typer.Typer(help="Evidence lifecycle management")
app.add_typer(evidence_app, name="evidence")


@evidence_app.command("release")
def evidence_release(
    engagement_id: str = typer.Argument(...),
    evidence_id: str = typer.Argument(...),
    reviewer: str = typer.Option("operator", "--reviewer"),
    notes: str = typer.Option("", "--notes",
        help="Optional reviewer notes for the audit record."),
) -> None:
    """Release a held_for_review artifact to redacted status.

    Refuses if the artifact is not held_for_review (idempotent-safe:
    releasing an already-released artifact is a no-op with a message).
    """
    from sentinel.evidence.store import (
        release_held_artifact, EvidenceCrossEngagement,
    )
    db = _db()
    try:
        row = db.connection.execute(
            "SELECT redaction_status FROM artifacts "
            "WHERE id = ? AND engagement_id = ?",
            (evidence_id, engagement_id),
        ).fetchone()
        if row is None:
            console.print(
                f"[red]No artifact {evidence_id!r} in engagement "
                f"{engagement_id!r}[/]"
            )
            raise typer.Exit(1)
        if row["redaction_status"] != "held_for_review":
            console.print(
                f"[yellow]Already released:[/] {evidence_id} status="
                f"{row['redaction_status']!r} (no-op)"
            )
            return
        try:
            release_held_artifact(
                db, evidence_id,
                engagement_id=engagement_id,
                reviewer=reviewer,
            )
        except EvidenceCrossEngagement as e:
            console.print(f"[red]Cross-engagement refused:[/] {e}")
            raise typer.Exit(1)
        console.print(
            f"[green]Released[/] {evidence_id} by {reviewer}"
        )
        if notes:
            console.print(f"Notes: {notes}")
    finally:
        db.close()


# (v3-follow-up, NVD foundation) Local CVE cache — single-ID sync.
# Full NVD bulk sync / incremental / CWE / CAPEC / ATT&CK all deferred.

knowledge_app = typer.Typer(help="Knowledge base and CVE cache")
app.add_typer(knowledge_app, name="knowledge")


@knowledge_app.command("sync-cve")
def knowledge_sync_cve(
    cve_id: str = typer.Argument(..., help="e.g. CVE-2024-1234"),
    actor: str = typer.Option("operator", "--actor"),
) -> None:
    """Fetch one CVE from NVD and cache it locally.

    Three-state validator behavior:
      - Cached with vuln_status != 'INVALID' → VERIFIED (kept)
      - Not cached                              → UNVERIFIED (kept, tagged)
      - Cached as INVALID (this command on 404) → INVALID (dropped)

    Prior help text incorrectly said unknown CVEs are dropped; under
    the three-state validator they are retained as unverified. Only
    explicitly-INVALID CVEs are dropped.
    """
    from sentinel.knowledge.nvd import (
        fetch_cve, store_cve, NvdError, NvdCveNotFound,
        mark_cve_invalid, record_sync_attempt,
    )
    from sentinel.audit.store import AuditStore
    db = _db()
    try:
        try:
            cve = fetch_cve(cve_id)
        except NvdCveNotFound as e:
            # (v4.3) Persist the negative result so the three-state
            # validator will drop hallucinated CVEs on next triage.
            # Prior version exited without persisting anything, so a
            # CVE could be hallucinated repeatedly.
            mark_cve_invalid(db, cve_id.upper(), reason=str(e))
            record_sync_attempt(
                db, cve_id=cve_id, outcome="not_found", actor=actor,
                detail=str(e), record_status="INVALID",
            )
            AuditStore(db).append(
                engagement_id="system", actor=actor,
                event_type="cve_marked_invalid", decision="ok",
                details={"cve_id": cve_id.upper(), "reason": str(e)},
            )
            console.print(
                f"[yellow]CVE {cve_id.upper()} not found in NVD[/] — "
                f"marked INVALID in local cache. Future triage runs will "
                f"drop this reference."
            )
            raise typer.Exit(1)
        except NvdError as e:
            record_sync_attempt(
                db, cve_id=cve_id, outcome="transient_error", actor=actor,
                detail=str(e),
            )
            AuditStore(db).append(
                engagement_id="system", actor=actor,
                event_type="cve_sync_failed", decision="unverified",
                details={"cve_id": cve_id.upper(), "reason": str(e)},
            )
            console.print(
                f"[yellow]UNVERIFIED — NVD fetch failed; local CVE truth "
                f"was not changed:[/] {e}"
            )
            raise typer.Exit(1)
        store_cve(db, cve)
        is_rejected = cve.vuln_status.strip().upper() in {"REJECTED", "INVALID"}
        record_sync_attempt(
            db, cve_id=cve.cve_id,
            outcome="rejected" if is_rejected else "verified",
            actor=actor, detail=f"NVD vulnStatus={cve.vuln_status!r}",
            record_status=cve.vuln_status,
        )
        AuditStore(db).append(
            engagement_id="system", actor=actor,
            event_type="cve_sync", decision="rejected" if is_rejected else "verified",
            details={"cve_id": cve.cve_id, "source": "nvd-api-2.0",
                     "vuln_status": cve.vuln_status},
        )
        label = "Rejected" if is_rejected else "Verified"
        style = "yellow" if is_rejected else "green"
        console.print(f"[{style}]{label} and cached[/] {cve.cve_id}")
        console.print(f"  status: {cve.vuln_status}")
        console.print(f"  published: {cve.published_utc}")
        if cve.cvss_score is not None:
            console.print(
                f"  cvss: {cve.cvss_score} ({cve.cvss_severity or 'n/a'})"
            )
        console.print(f"  description: {cve.description[:120]}")
    finally:
        db.close()


@knowledge_app.command("list-cves")
def knowledge_list_cves(
    limit: int = typer.Option(20, "--limit"),
) -> None:
    """List cached CVE entries."""
    db = _db()
    try:
        rows = db.connection.execute(
            "SELECT cve_id, vuln_status, cvss_score, "
            "substr(description, 1, 60) AS desc "
            "FROM cve_entries ORDER BY fetched_at_utc DESC LIMIT ?",
            (limit,),
        ).fetchall()
        if not rows:
            console.print(
                "[yellow]No CVE entries cached.[/] "
                "Sync with: sentinel knowledge sync-cve CVE-YYYY-NNNN"
            )
            return
        table = Table("CVE", "NVD status", "CVSS", "Description")
        for r in rows:
            score = f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else "—"
            status = str(r["vuln_status"] or "UNVERIFIED").upper()
            table.add_row(r["cve_id"], status, score, r["desc"])
        console.print(table)
    finally:
        db.close()


@knowledge_app.command("list")
def knowledge_list() -> None:
    """List current knowledge revisions and their independent review state."""
    db = _db()
    try:
        rows = db.connection.execute(
            "SELECT e.id, r.title, r.topic, r.source_url, "
            "COALESCE(kr.decision, 'unreviewed') AS review_decision "
            "FROM knowledge_entries e "
            "JOIN knowledge_revisions r ON r.revision_id=e.current_revision_id "
            "LEFT JOIN knowledge_reviews kr ON kr.review_id=("
            "  SELECT kr2.review_id FROM knowledge_reviews kr2 "
            "  WHERE kr2.revision_id=r.revision_id "
            "  ORDER BY kr2.reviewed_at_utc DESC, kr2.review_id DESC LIMIT 1) "
            "ORDER BY e.id"
        ).fetchall()
        if not rows:
            console.print("(no knowledge entries)")
            return
        table = Table("Entry ID", "Review", "Topic", "Title", "Source")
        for row in rows:
            table.add_row(
                row["id"], row["review_decision"], row["topic"],
                row["title"], row["source_url"],
            )
        console.print(table)
    finally:
        db.close()


@knowledge_app.command("review")
def knowledge_review(
    entry_id: str = typer.Argument(..., help="Knowledge entry id (kb_… )"),
    decision: str = typer.Option(..., "--decision", help="approved | rejected"),
    rationale: str = typer.Option(..., "--rationale"),
    reviewer: str = typer.Option(..., "--reviewer",
        help="Reviewer label; attribution only, not authenticated identity."),
) -> None:
    """Independently review the current immutable knowledge revision."""
    from sentinel.knowledge.provenance import (
        review_revision, KnowledgeReviewError,
    )
    db = _db()
    try:
        try:
            review_id = review_revision(
                db, entry_id, reviewer=reviewer, decision=decision,
                rationale=rationale,
            )
        except KnowledgeReviewError as e:
            console.print(f"[red]Review refused:[/] {e}")
            raise typer.Exit(1)
        console.print(
            f"[green]Review recorded[/] {review_id} for {entry_id}: {decision}"
        )
    finally:
        db.close()


# (v3-follow-up, Bug 5) Top-level `sentinel findings` sub-app that
# aliases the existing `sentinel triage findings/show/transition`
# commands. Operator-facing workflows expect `sentinel findings list
# <eng>`, not `sentinel triage findings <eng>`. Both work — same code
# path, one extra namespace.

findings_app = typer.Typer(help="Findings (alias for triage findings/show/transition)")
app.add_typer(findings_app, name="findings")


@findings_app.command("list")
def findings_list_alias(
    engagement_id: str = typer.Argument(...),
) -> None:
    """List findings for an engagement. Alias for `triage findings`."""
    findings_list(engagement_id)


@findings_app.command("show")
def findings_show_alias(
    finding_id: str = typer.Argument(...),
) -> None:
    """Show one finding. Alias for `triage show`."""
    finding_show(finding_id)


@findings_app.command("transition")
def findings_transition_alias(
    finding_id: str = typer.Argument(...),
    to_state: str = typer.Option(..., "--to",
        help="Target lifecycle state (candidate|ready_for_review|"
             "human_validated|report_ready|submitted|rejected)."),
    actor: str = typer.Option("operator", "--actor"),
    rationale: str = typer.Option("", "--rationale"),
) -> None:
    """Transition a finding's lifecycle state. Alias for `triage transition`."""
    # Delegate to the existing implementation — its signature is stable.
    finding_transition(
        finding_id=finding_id, to_state=to_state,
        actor=actor, rationale=rationale,
    )


if __name__ == "__main__":
    app()
