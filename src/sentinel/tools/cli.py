# SPDX-License-Identifier: Apache-2.0
"""Tool manifest management CLI.

Closes the reviewer's Priority 4: "manifest registration and validation
commands" replacing "programmatic manifest registration" with a CLI path.

Commands:
  register   -- compute hash from a binary, register manifest
  list       -- show all registered manifests
  verify     -- re-check a manifest's binary hash against disk
  deregister -- remove a manifest (refused if any approval references it)

`register` is the "rotate" mechanism: when a tool updates, register the
new version alongside the old one. Old approvals stay valid against the
old version; new approvals use the new version. No in-place rotation
because approvals bind to `(tool_name, tool_version)` and to
`manifest_hash`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

import typer
from rich.console import Console

from sentinel.storage.db import Database
from sentinel.tools.manifests import ManifestStore, ToolManifest


console = Console()


def register_tool_cli(
    app: typer.Typer,
    db_factory: Callable[[], Database],
) -> None:
    """Register the `sentinel tool` sub-app against the given Typer app.

    db_factory is the same factory `sentinel.cli` uses for its other
    commands. Passing it in avoids a circular import while keeping tests
    able to patch one entry point (`sentinel.cli._db`).
    """
    tool_app = typer.Typer(
        name="tool",
        help="Manage tool manifests (register / list / verify / deregister).",
    )

    @tool_app.command("register")
    def register(
        executable_path: str = typer.Argument(
            ...,
            help="Absolute path to the tool's executable.",
        ),
        tool: str = typer.Option(
            ..., "--tool", help="Tool name (matches adapter's TOOL_NAME constant)."
        ),
        version: str = typer.Option(
            ..., "--version", help="Tool version string (matched by adapter)."
        ),
        execution_class: int = typer.Option(
            0, "--class", help="Execution class 0..3 (ECR §5.2)."
        ),
        network: bool = typer.Option(
            False, "--network", help="Manifest declares network_access=True."
        ),
        profile: list[str] = typer.Option(
            None, "--profile", help="Allowed operation profile. Repeat for multiple."
        ),
        provider: list[str] = typer.Option(
            None,
            "--provider",
            help="Declared infrastructure endpoint (e.g. crt.sh). "
            "Repeat for multiple. Does NOT authorize the provider "
            "for an engagement — that needs --provider on "
            "`sentinel approval issue`.",
        ),
        prohibited: list[str] = typer.Option(
            None,
            "--prohibited",
            help="Token refused at runtime (single-token match). Repeat for multiple.",
        ),
        max_runtime_seconds: int = typer.Option(60, "--max-runtime-seconds"),
        max_output_megabytes: int = typer.Option(10, "--max-output-megabytes"),
        output_format: str = typer.Option("text", "--format"),
        actor: str = typer.Option("operator", "--actor"),
    ) -> None:
        """Compute SHA-256 of a binary and register its manifest.

        Refuses if `(tool, version)` is already registered. To update a
        tool, register a NEW version — approvals are bound to
        (tool, version) and (manifest_hash), so in-place rotation would
        orphan them.
        """
        db = db_factory()
        try:
            p = Path(executable_path)
            if not p.is_file():
                console.print(f"[red]Binary not found:[/] {p}")
                raise typer.Exit(1)

            try:
                h = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError as e:
                console.print(f"[red]Cannot read binary:[/] {e}")
                raise typer.Exit(1)

            if not (0 <= execution_class <= 3):
                console.print(f"[red]--class must be 0..3[/] (got {execution_class})")
                raise typer.Exit(1)

            if execution_class >= 2 and not network:
                console.print(
                    f"[yellow]Warning:[/] execution_class={execution_class} "
                    f"but --network is not set. Class >=2 usually implies "
                    f"network_access=True. Not refusing; operator may have "
                    f"a local-only Class 2 tool."
                )

            store = ManifestStore(db)
            existing = store.get_by_tool_version(tool, version)
            if existing is not None:
                console.print(
                    f"[red]Already registered:[/] {tool} {version} (id={existing.id})."
                )
                console.print(
                    "Register a new --version instead; approvals bind to "
                    "(tool_name, tool_version) and manifest_hash."
                )
                raise typer.Exit(1)

            manifest = ToolManifest(
                tool_name=tool,
                version=version,
                executable_path=str(p.resolve()),
                executable_sha256=h,
                execution_class=execution_class,
                network_access=network,
                allowed_profiles=tuple(profile or ()),
                prohibited=tuple(prohibited or ()),
                limits={
                    "max_runtime_seconds": max_runtime_seconds,
                    "max_output_megabytes": max_output_megabytes,
                },
                output_format=output_format,
                infrastructure_endpoints=tuple(provider or ()),
            )
            reg = store.register(manifest, actor=actor)
            ok, reason = store.verify(reg.id)
            if not ok:
                console.print(f"[red]Registered but verify() failed:[/] {reason}")
                raise typer.Exit(1)

            console.print(f"[green]Registered[/] {reg.id}")
            console.print(f"  tool         : {tool} {version}")
            console.print(f"  binary       : {p.resolve()}")
            console.print(f"  sha256       : {h[:16]}...")
            console.print(f"  class        : {execution_class}  network: {network}")
            console.print(f"  profiles     : {list(profile or [])}")
            console.print(f"  providers    : {list(provider or [])}")
            console.print(f"  prohibited   : {list(prohibited or [])}")
        finally:
            db.close()

    @tool_app.command("list")
    def list_() -> None:
        """Show every registered manifest."""
        db = db_factory()
        try:
            rows = db.connection.execute(
                "SELECT id, tool_name, version, execution_class, "
                "network_access, substr(executable_sha256, 1, 16) "
                "AS sha16, executable_path, manifest_hash "
                "FROM tool_manifests ORDER BY tool_name, version"
            ).fetchall()
            if not rows:
                console.print("[yellow]No manifests registered.[/]")
                console.print(
                    "  Register with: sentinel tool register <path> "
                    "--tool <name> --version <v>"
                )
                return
            console.print(f"[green]{len(rows)} manifest(s) registered[/]")
            console.print()
            for r in rows:
                console.print(f"  {r['tool_name']} {r['version']}")
                console.print(
                    f"    id={r['id']}  class={r['execution_class']}  "
                    f"network={bool(r['network_access'])}  "
                    f"sha256={r['sha16']}..."
                )
                console.print(f"    binary={r['executable_path']}")
                console.print(f"    manifest_hash={r['manifest_hash'][:16]}...")
        finally:
            db.close()

    @tool_app.command("verify")
    def verify(
        tool: str = typer.Argument(...),
        version: str = typer.Argument(...),
    ) -> None:
        """Re-verify a manifest's DB row and its binary's on-disk hash."""
        db = db_factory()
        try:
            store = ManifestStore(db)
            reg = store.get_by_tool_version(tool, version)
            if reg is None:
                console.print(f"[red]No manifest[/] for {tool} {version}")
                raise typer.Exit(1)

            ok, reason = store.verify(reg.id)
            if not ok:
                console.print(f"[red]Manifest row integrity FAILED:[/] {reason}")
                raise typer.Exit(1)
            console.print(
                f"[green]Manifest row integrity OK[/] "
                f"({reg.id} {reg.manifest_hash[:16]}...)"
            )

            binary = Path(reg.manifest.executable_path)
            if not binary.is_file():
                console.print(f"[red]Binary missing:[/] {binary}")
                raise typer.Exit(1)
            try:
                actual = hashlib.sha256(binary.read_bytes()).hexdigest()
            except OSError as e:
                console.print(f"[red]Cannot read binary:[/] {e}")
                raise typer.Exit(1)
            if actual != reg.manifest.executable_sha256:
                console.print("[red]Binary digest MISMATCH[/]")
                console.print(f"  expected: {reg.manifest.executable_sha256[:16]}...")
                console.print(f"  actual  : {actual[:16]}...")
                console.print(
                    f"  The binary at {binary} was modified after "
                    f"registration. Re-register a new version, or "
                    f"restore the pinned binary."
                )
                raise typer.Exit(1)
            console.print(f"[green]Binary digest OK[/] ({binary} -> {actual[:16]}...)")
        finally:
            db.close()

    @tool_app.command("deregister")
    def deregister(
        tool: str = typer.Argument(...),
        version: str = typer.Argument(...),
        yes: bool = typer.Option(
            False, "--yes", "-y", help="Skip interactive confirmation."
        ),
    ) -> None:
        """Remove a manifest. Refused if any approval still references it."""
        db = db_factory()
        try:
            store = ManifestStore(db)
            reg = store.get_by_tool_version(tool, version)
            if reg is None:
                console.print(f"[red]No manifest[/] for {tool} {version}")
                raise typer.Exit(1)

            active_approvals = db.connection.execute(
                "SELECT approval_id FROM approvals "
                "WHERE tool_name = ? AND tool_version = ? "
                "AND revoked_at_utc IS NULL",
                (tool, version),
            ).fetchall()
            if active_approvals:
                console.print(
                    f"[red]Refused:[/] {len(active_approvals)} "
                    f"unrevoked approval(s) reference {tool} {version}:"
                )
                for a in active_approvals[:5]:
                    console.print(f"  {a['approval_id']}")
                if len(active_approvals) > 5:
                    console.print(f"  ... and {len(active_approvals) - 5} more")
                console.print(
                    "  Revoke them first: sentinel approval revoke <approval_id>"
                )
                raise typer.Exit(1)

            if not yes:
                msg = (
                    f"Deregister {tool} {version} (id={reg.id})? "
                    f"Existing approvals (including revoked) will retain "
                    f"an un-resolvable tool reference in their audit "
                    f"record."
                )
                if not typer.confirm(msg, default=False):
                    console.print("[yellow]Aborted.[/]")
                    raise typer.Exit(1)

            with db.transaction() as conn:
                conn.execute(
                    "DELETE FROM tool_manifests WHERE id = ?",
                    (reg.id,),
                )
            console.print(f"[green]Deregistered[/] {tool} {version} ({reg.id})")
        finally:
            db.close()

    app.add_typer(tool_app, name="tool")
