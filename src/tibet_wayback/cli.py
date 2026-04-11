"""
Wayback CLI — Time-travel from your terminal.
===============================================

    $ wayback seal "before migration"
    $ wayback list
    $ wayback restore wb-3f8a
    $ wayback diff wb-3f8a wb-7c2d
    $ wayback audit wb-3f8a --framework iso42001
    $ wayback sbom
    $ wayback sbom wb-3f8a
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .core import Wayback

app = typer.Typer(
    name="wayback",
    help="System state time-travel. Seal any moment, restore any moment.",
    no_args_is_help=True,
)
console = Console()


def _get_wayback(path: str) -> Wayback:
    return Wayback(path)


# ── seal ────────────────────────────────────────────────────────────

@app.command()
def seal(
    label: str = typer.Argument("", help="Human-readable label for this moment"),
    path: str = typer.Option(".", "--path", "-p", help="Directory to seal"),
    audit: bool = typer.Option(False, "--audit", "-a", help="Include tibet-audit results"),
    services: bool = typer.Option(True, "--services/--no-services", help="Capture service manifest"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Tag this seal"),
    notes: str = typer.Option("", "--notes", "-n", help="Additional notes"),
    phantom: bool = typer.Option(False, "--phantom", help="Also seal as Phantom session for cross-device resume"),
):
    """Seal the current system state."""
    wb = _get_wayback(path)

    with console.status("[bold green]Sealing system state..."):
        s = wb.seal(
            label=label,
            include_audit=audit,
            include_services=services,
            tags=[tag] if tag else [],
            notes=notes,
        )

    # Display result
    lines = []
    lines.append(f"[bold green]✓ Sealed[/] [bold]{s.seal_id}[/]")
    if s.label:
        lines.append(f"  Label: {s.label}")
    lines.append(f"  Path: {s.path}")
    if s.snapshot:
        lines.append(f"  Files: {len(s.snapshot.file_hashes)} (manifest: {s.snapshot.manifest_hash[:12]}...)")
    if s.git_commit:
        lines.append(f"  Git: {s.git_branch} @ {s.git_commit}")
    if s.git_stash:
        lines.append(f"  Stashed dirty files: {s.git_stash[:8]}")
    if s.service_manifest:
        svc_count = sum(1 for k in s.service_manifest if not k.startswith("_"))
        lines.append(f"  Services: {svc_count} running")
    if s.tibet_token_id:
        lines.append(f"  TIBET: {s.tibet_token_id}")
    if s.airlock_snapshot_id:
        lines.append(f"  Airlock: {s.airlock_snapshot_id}")
    if s.snapshot and s.snapshot.audit_score is not None:
        lines.append(f"  Audit: {s.snapshot.audit_grade} ({s.snapshot.audit_score}%)")

    console.print(Panel("\n".join(lines), title="Wayback Seal", border_style="green"))
    # Phantom cross-device seal
    if phantom:
        try:
            phantom_id = wb.phantom_seal(s)
            console.print(f"\n  [bold magenta]Phantom:[/] Session sealed — resume on any device")
            console.print(f"  Resume:  [bold]wayback resume {s.seal_id}[/]")
        except Exception as e:
            console.print(f"\n  [dim]Phantom seal failed: {e}[/]")

    console.print(f"\n  Restore: [bold]wayback restore {s.seal_id}[/]")
    console.print(f"  Compare: [bold]wayback diff {s.seal_id} <other>[/]")


# ── resume (Phantom) ───────────────────────────────────────────────

@app.command()
def resume(
    seal_id: str = typer.Argument(..., help="Seal ID to resume (e.g. wb-3f8a)"),
    path: str = typer.Option(".", "--path", "-p"),
    backend: Optional[str] = typer.Option(None, "--backend", "-b", help="Compute backend (gpu, claude, gemini, ollama)"),
):
    """Resume a sealed session on this device (via Phantom)."""
    wb = _get_wayback(path)
    seal = wb.timeline.get(seal_id)

    if not seal:
        console.print(f"[red]Seal '{seal_id}' not found.[/]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold]{seal.seal_id}[/] — {seal.label or '(no label)'}\n"
        f"Sealed: {seal.timestamp.strftime('%Y-%m-%d %H:%M:%S')} ({seal.age})\n"
        f"Git: {seal.git_branch}@{seal.git_commit}",
        title="Resuming Session",
        border_style="magenta",
    ))

    with console.status("[bold magenta]Resuming via Phantom..."):
        result = wb.phantom_resume(seal, backend=backend)

    if result.get("error"):
        console.print(f"[red]{result['error']}[/]")
        raise typer.Exit(1)

    lines = [f"[bold green]✓ Session resumed[/]"]
    if result.get("session_id"):
        lines.append(f"  Phantom session: {result['session_id']}")
    if result.get("backend"):
        lines.append(f"  Backend: {result['backend']}")
    for item in result.get("restored", []):
        lines.append(f"  [green]✓[/] {item}")

    console.print(Panel("\n".join(lines), title="Phantom Resume", border_style="magenta"))


# ── list ────────────────────────────────────────────────────────────

@app.command("list")
def list_seals(
    path: str = typer.Option(".", "--path", "-p"),
    limit: int = typer.Option(20, "--limit", "-l"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t"),
):
    """List sealed moments."""
    wb = _get_wayback(path)
    seals = wb.list_seals(limit=limit, tag=tag)

    if not seals:
        console.print("[dim]No seals yet. Create one with:[/] wayback seal \"my label\"")
        return

    table = Table(title=f"Wayback Timeline — {len(seals)} seal(s)")
    table.add_column("Seal ID", style="bold cyan")
    table.add_column("Age")
    table.add_column("Label")
    table.add_column("Git")
    table.add_column("Files")
    table.add_column("Services")
    table.add_column("Audit")
    table.add_column("TIBET")

    for s in seals:
        git_info = f"{s.git_branch}@{s.git_commit}" if s.git_commit else "—"
        file_count = str(len(s.snapshot.file_hashes)) if s.snapshot else "—"
        svc_count = str(sum(1 for k in s.service_manifest if not k.startswith("_"))) if s.service_manifest else "—"
        audit_info = f"{s.snapshot.audit_grade}" if s.snapshot and s.snapshot.audit_score is not None else "—"
        tibet_info = "✓" if s.tibet_token_id else "—"
        tags_str = f" [{','.join(s.tags)}]" if s.tags else ""

        table.add_row(
            s.seal_id,
            s.age,
            (s.short_label + tags_str) or "—",
            git_info,
            file_count,
            svc_count,
            audit_info,
            tibet_info,
        )

    console.print(table)


# ── restore ─────────────────────────────────────────────────────────

@app.command()
def restore(
    seal_id: str = typer.Argument(..., help="Seal ID to restore (e.g. wb-3f8a)"),
    path: str = typer.Option(".", "--path", "-p"),
    git: bool = typer.Option(True, "--git/--no-git", help="Restore git state"),
    services: bool = typer.Option(False, "--services", help="Restart services to match sealed state"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Restore system to a sealed state."""
    wb = _get_wayback(path)
    seal = wb.timeline.get(seal_id)

    if not seal:
        console.print(f"[red]Seal '{seal_id}' not found.[/]")
        raise typer.Exit(1)

    # Show what will be restored
    console.print(Panel(
        f"[bold]{seal.seal_id}[/] — {seal.label or '(no label)'}\n"
        f"Sealed: {seal.timestamp.strftime('%Y-%m-%d %H:%M:%S')} ({seal.age})\n"
        f"Git: {seal.git_branch}@{seal.git_commit}\n"
        f"Restore git: {'yes' if git else 'no'}\n"
        f"Restore services: {'yes' if services else 'no'}",
        title="Restore Target",
        border_style="yellow",
    ))

    if not force:
        confirm = typer.confirm("Proceed with restore?")
        if not confirm:
            console.print("[dim]Cancelled.[/]")
            raise typer.Exit(0)

    with console.status("[bold yellow]Restoring..."):
        result = wb.restore(seal_id, restore_git=git, restore_services=services)

    if result.get("error"):
        console.print(f"[red]Error: {result['error']}[/]")
        raise typer.Exit(1)

    # Display results
    lines = [f"[bold green]✓ Restored to {seal.seal_id}[/]"]
    for item in result.get("restored", []):
        lines.append(f"  [green]✓[/] {item}")
    for item in result.get("skipped", []):
        lines.append(f"  [dim]— {item} (skipped)[/]")
    for item in result.get("errors", []):
        lines.append(f"  [red]✗ {item}[/]")

    console.print(Panel("\n".join(lines), title="Restore Complete", border_style="green"))


# ── diff ────────────────────────────────────────────────────────────

@app.command()
def diff(
    seal_a: str = typer.Argument(..., help="First seal ID"),
    seal_b: str = typer.Argument(..., help="Second seal ID"),
    path: str = typer.Option(".", "--path", "-p"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Compare two sealed moments."""
    wb = _get_wayback(path)
    d = wb.diff(seal_a, seal_b)

    if not d:
        console.print("[red]Could not compare — one or both seals not found.[/]")
        raise typer.Exit(1)

    if json_output:
        print(json.dumps(d.to_dict(), indent=2, default=str))
        return

    # Header
    console.print(Panel(
        f"[bold]{d.seal_a}[/] → [bold]{d.seal_b}[/]\n"
        f"{d.timestamp_a.strftime('%Y-%m-%d %H:%M')} → {d.timestamp_b.strftime('%Y-%m-%d %H:%M')}",
        title="Wayback Diff",
        border_style="blue",
    ))

    # File changes
    table = Table(title="File Changes")
    table.add_column("Type", style="bold")
    table.add_column("Count")
    table.add_column("Files")

    if d.added_files:
        table.add_row("[green]+Added[/]", str(len(d.added_files)),
                       ", ".join(d.added_files[:5]) + ("..." if len(d.added_files) > 5 else ""))
    if d.removed_files:
        table.add_row("[red]-Removed[/]", str(len(d.removed_files)),
                       ", ".join(d.removed_files[:5]) + ("..." if len(d.removed_files) > 5 else ""))
    if d.modified_files:
        table.add_row("[yellow]~Modified[/]", str(len(d.modified_files)),
                       ", ".join(d.modified_files[:5]) + ("..." if len(d.modified_files) > 5 else ""))
    table.add_row("[dim]Unchanged[/]", str(d.unchanged_files), "")

    console.print(table)

    # Package version changes — the debugging goldmine
    if d.packages_upgraded or d.packages_downgraded or d.packages_added or d.packages_removed:
        pkg_table = Table(title="Package Changes")
        pkg_table.add_column("Package", style="bold cyan")
        pkg_table.add_column("Change")
        pkg_table.add_column("Versions")

        for name, ver in sorted(d.packages_upgraded.items()):
            pkg_table.add_row(name, "[yellow]upgraded[/]", ver)
        for name, ver in sorted(d.packages_downgraded.items()):
            pkg_table.add_row(name, "[red]downgraded[/]", ver)
        for name, ver in sorted(d.packages_added.items()):
            pkg_table.add_row(name, "[green]+added[/]", ver)
        for name, ver in sorted(d.packages_removed.items()):
            pkg_table.add_row(name, "[red]-removed[/]", ver)

        console.print(pkg_table)

    # Service memory delta
    if d.services_memory_delta:
        mem_table = Table(title="Service Memory Changes")
        mem_table.add_column("Service", style="bold")
        mem_table.add_column("Memory")

        for name, delta in sorted(d.services_memory_delta.items()):
            inner = delta.split("(")[1] if "(" in delta else ""
            color = "red" if "+" in inner else "green"
            mem_table.add_row(name, f"[{color}]{delta}[/]")

        console.print(mem_table)

    # Git changes
    if d.git_branch_changed:
        console.print("[yellow]Branch changed between seals[/]")

    # Service start/stop changes
    if d.services_started or d.services_stopped:
        console.print()
        if d.services_started:
            console.print(f"[green]Services started:[/] {', '.join(d.services_started)}")
        if d.services_stopped:
            console.print(f"[red]Services stopped:[/] {', '.join(d.services_stopped)}")

    # Port changes
    if d.ports_opened or d.ports_closed:
        console.print()
        if d.ports_opened:
            console.print(f"[green]Ports opened:[/] {', '.join(d.ports_opened)}")
        if d.ports_closed:
            console.print(f"[red]Ports closed:[/] {', '.join(d.ports_closed)}")

    # Audit delta
    if d.score_delta is not None:
        color = "green" if d.score_delta > 0 else "red" if d.score_delta < 0 else "dim"
        arrow = "+" if d.score_delta > 0 else ""
        console.print(f"\nAudit: [{color}]{arrow}{d.score_delta}[/] ({d.grade_a} → {d.grade_b})")

    console.print(f"\n[bold]Summary:[/] {d.summary}")


# ── audit ───────────────────────────────────────────────────────────

@app.command()
def audit(
    seal_id: str = typer.Argument(..., help="Seal ID to audit"),
    path: str = typer.Option(".", "--path", "-p"),
    framework: str = typer.Option("", "--framework", "-f", help="Compliance framework (e.g. iso42001)"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Replay an audit against a sealed state."""
    wb = _get_wayback(path)

    with console.status("[bold]Running audit..."):
        result = wb.audit(seal_id, framework=framework)

    if not result:
        console.print(f"[red]Seal '{seal_id}' not found.[/]")
        raise typer.Exit(1)

    if json_output:
        print(json.dumps(result, indent=2, default=str))
        return

    lines = [
        f"Seal: [bold]{result['seal_id']}[/] — {result.get('label', '')}",
        f"Sealed: {result['timestamp']}",
    ]

    if result.get("audit"):
        a = result["audit"]
        source = a.get("source", "unknown")
        lines.append(f"Score: [bold]{a.get('score', '?')}%[/] ({a.get('grade', '?')})")
        lines.append(f"Checks: {a.get('checks', '?')}")
        lines.append(f"Source: {'from seal' if source == 'sealed' else 'live scan'}")
    else:
        lines.append("[dim]No audit data available[/]")

    if result.get("compliance"):
        c = result["compliance"]
        lines.append(f"\nFramework: {framework}")
        lines.append(f"Coverage: {c.get('coverage', '?')}%")

    console.print(Panel("\n".join(lines), title="Wayback Audit", border_style="magenta"))


# ── sbom ────────────────────────────────────────────────────────────

@app.command()
def sbom(
    seal_id: Optional[str] = typer.Argument(None, help="Seal ID (omit for current state)"),
    path: str = typer.Option(".", "--path", "-p"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    json_output: bool = typer.Option(False, "--json", help="Raw JSON output"),
):
    """Generate SBOM-style system manifest."""
    wb = _get_wayback(path)

    with console.status("[bold]Capturing system manifest..."):
        result = wb.sbom(seal_id)

    if result.get("error"):
        console.print(f"[red]{result['error']}[/]")
        raise typer.Exit(1)

    if json_output or output:
        data = json.dumps(result, indent=2, default=str)
        if output:
            Path(output).write_text(data)
            console.print(f"[green]SBOM written to {output}[/]")
        else:
            print(data)
        return

    # Rich display
    sys_info = result.get("system", {})
    console.print(Panel(
        f"Hostname: [bold]{sys_info.get('hostname', '?')}[/]\n"
        f"Platform: {sys_info.get('platform', '?')}\n"
        f"Python: {sys_info.get('python', '?')}",
        title="System",
        border_style="blue",
    ))

    git = result.get("git")
    if git:
        dirty = " [yellow](dirty)[/]" if git.get("is_dirty") else ""
        console.print(f"Git: {git.get('branch', '?')}@{git.get('commit', '?')}{dirty}")

    files = result.get("files", {})
    console.print(f"Files: {files.get('count', 0)} (hash: {files.get('manifest_hash', '?')[:12]}...)")

    # Services table
    services = result.get("services", {})
    if services:
        table = Table(title="Service Manifest")
        table.add_column("Service", style="bold")
        table.add_column("Type")
        table.add_column("PID")
        table.add_column("Memory")
        table.add_column("Started")

        for name, info in sorted(services.items()):
            if name.startswith("_"):
                continue
            mem = f"{info.get('memory_mb', '?')} MB" if info.get('memory_mb') else "—"
            table.add_row(
                name,
                info.get("type", "?"),
                str(info.get("pid", "—")),
                mem,
                info.get("started", "—")[:19] if info.get("started") else "—",
            )

        console.print(table)

    # Tibet packages
    tibet_pkgs = services.get("_tibet_packages", {}).get("packages", {})
    if tibet_pkgs:
        console.print()
        table = Table(title="TIBET Packages")
        table.add_column("Package", style="bold cyan")
        table.add_column("Version")
        for name, ver in sorted(tibet_pkgs.items()):
            table.add_row(name, ver)
        console.print(table)

    # Listening ports
    ports_info = services.get("_listening_ports", {}).get("ports", [])
    if ports_info:
        console.print(f"\nListening: {', '.join(ports_info[:10])}")

    audit_info = result.get("audit")
    if audit_info:
        console.print(f"\nAudit: {audit_info.get('grade', '?')} ({audit_info.get('score', '?')}%)")


# ── Entry point ─────────────────────────────────────────────────────

def main():
    app()


if __name__ == "__main__":
    main()
