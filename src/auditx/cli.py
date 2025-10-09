from __future__ import annotations
import json
import os
import shlex
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Sequence
import typer
from rich import box
from rich.console import Console
from rich.pretty import Pretty
from rich.table import Table
from rich.text import Text
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.status import Status as RichStatus

from .core.models import RunContext, Status, Severity
from .core.discovery import iter_local_checks, iter_entrypoint_checks
from .core.runner import run_all
from .core.reporting import docs_to_html, to_html, to_json, to_markdown
from .core import config as cfg
from .core.facts import FactStore, collect_facts, registered_techs
from .core.provider_loader import load_all_providers

app = typer.Typer(
    help="AuditX – Run pluggable checks for performance/security/config.",
    invoke_without_command=True,
)
console = Console()

# Auto-load all providers on startup (local + entry points)
load_all_providers()


def _summarize_fact_value(value: Any) -> Any:
    """Summarize a fact value for display in tables.
    
    For sequences of objects, shows count and sample labels.
    For long lists, shows just the count.
    Otherwise returns the value as-is.
    
    Args:
        value: The fact value to summarize
        
    Returns:
        A human-readable summary string or the original value
    """
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        seq = list(value)
        if not seq:
            return "0 object(s)"
        if all(isinstance(item, Mapping) for item in seq):
            labels: list[str] = []
            for item in seq:
                label = _extract_label(item)
                if label:
                    labels.append(label)
            summary = f"{len(seq)} object(s)"
            if labels:
                # Show up to 3 sample labels
                sample = ", ".join(labels[:3])
                if len(labels) > 3:
                    sample += "…"
                summary += f" (sample: {sample})"
            return summary
        # For long lists that aren't object mappings, just show the count
        if len(seq) > 10:
            return f"list ({len(seq)} items)"
    return value


def _extract_label(item: Mapping[str, Any]) -> str:
    """Extract a human-readable label from a mapping.
    
    Looks for common identifying keys (name, id, key, host) and
    returns the first non-empty value found.
    
    Args:
        item: Dictionary-like object to extract label from
        
    Returns:
        String label or empty string if no suitable key found
    """
    for key in ("name", "id", "key", "host"):
        value = item.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _ensure_config(cfg_data: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure configuration is present, prompting user if necessary.
    
    If configuration is missing and we're in a TTY environment, prompts
    the user for required parameters. Otherwise, displays an error and exits.
    
    Args:
        cfg_data: Current configuration dictionary
        
    Returns:
        Configuration dictionary with all required values
        
    Raises:
        typer.Exit: If configuration is missing and can't be collected interactively
    """
    if cfg_data:
        return cfg_data

    template = cfg.load_default_template()
    if not template:
        console.print("[red]No configuration found. Copy config/auditx.yaml.default to config/auditx.yaml and retry.[/]")
        raise typer.Exit(code=1)

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print("[red]Configuration is missing and interactive setup is not possible in this environment.[/]")
        console.print("Copy config/auditx.yaml.default to config/auditx.yaml and edit it, or use --set / AUDITX__... overrides.")
        raise typer.Exit(code=1)

    console.print("[yellow]No configuration provided. Let's collect the required parameters.[/]")
    combined: Dict[str, Any] = cfg.deep_merge({}, cfg_data)

    for tech, params in template.items():
        if not isinstance(params, dict):
            continue
        console.print(f"[bold]{tech}[/bold] parameters:")
        tech_cfg = dict(combined.get(tech, {}))
        for key, default in params.items():
            default_value = "" if default is None else str(default)
            current = tech_cfg.get(key)
            # Skip if already configured
            if isinstance(current, str) and current.strip():
                continue
            if current not in (None, "") and not isinstance(current, str):
                continue
            value = typer.prompt(
                f"{tech}.{key}",
                default=default_value,
                show_default=bool(default_value),
            ).strip()
            tech_cfg[key] = value
        combined[tech] = tech_cfg

    console.print("[green]Configuration captured for this run. Consider saving it under config/*.yaml for reuse.[/]")
    return combined


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.command.get_help(ctx))
        raise typer.Exit(code=0)

@app.command()
def run(
    tech: list[str] = typer.Option([], "--tech", help="Technologies to include (e.g., linux, zabbix, mysql)"),
    include: list[str] = typer.Option([], help="Only run checks whose id contains these substrings"),
    exclude: list[str] = typer.Option([], help="Skip checks whose id contains these substrings"),
    parallel: bool = typer.Option(True, help="Run checks in parallel"),
    format: str = typer.Option("table", help="Output format: table|json|md|html"),
    output: Optional[Path] = typer.Option(None, help="Write report to file instead of STDOUT"),
    plugins: bool = typer.Option(True, help="Load checks from entry points (auditx.checks)"),
    config_files: list[Path] = typer.Option(
        [],
        "--config",
        help="Configuration file(s) to load after defaults (can be passed multiple times)",
    ),
    vars_file: Optional[Path] = typer.Option(None, "--vars-file", help="YAML overrides with secrets"),
    set_kv: list[str] = typer.Option([], "--set", help="Override key=val (deep)"),
    ask_secrets: bool = typer.Option(False, "--ask-secrets", help="Prompt for missing secrets"),
    facts_cache: Optional[Path] = typer.Option(None, "--facts-cache", help="Persist facts to this JSON file"),
    facts_ttl: int = typer.Option(0, "--facts-ttl", help="Seconds; 0 = no TTL"),
    color: bool = typer.Option(True, "--color/--no-color", help="Colorize table output"),
    list_checks: bool = typer.Option(False, "--list-checks", help="List available checks after filters and exit"),
    show_duration: bool = typer.Option(True, "--show-duration/--no-show-duration", help="Display total execution time when finished"),
    progress: bool = typer.Option(True, "--progress/--no-progress", help="Show progress messages during execution"),
):
    """Run all discovered checks with optional filters."""
    started_at = datetime.now().astimezone()
    start_time = time.perf_counter()

    progress_console: Console | None = None
    status_spinner: RichStatus | None = None
    progress_log: list[str] = []
    checks_progress: Progress | None = None
    checks_task_id: int | None = None
    if progress:
        progress_console = Console(force_terminal=color, no_color=not color)
        status_spinner = progress_console.status("Preparing run…", spinner="dots")
        status_spinner.start()

    def emit_progress(message: str) -> None:
        nonlocal status_spinner, progress_log
        if status_spinner is not None:
            status_spinner.update(status=message)
            progress_log.append(message)
            return
        if not progress_console:
            return
        if color:
            progress_console.print(message, style="dim")
        else:
            progress_console.print(message)

    def stop_status_spinner() -> None:
        nonlocal status_spinner, progress_log
        if status_spinner is not None:
            status_spinner.stop()
            status_spinner = None
            if progress_console and progress_log:
                for line in progress_log:
                    if color:
                        progress_console.print(line, style="dim")
                    else:
                        progress_console.print(line)
        progress_log = []

    def make_fact_progress(tech_name: str) -> Callable[[str], None]:
        prefix = f"Collecting facts for '{tech_name}'"

        def _report(step: str) -> None:
            if status_spinner is not None:
                status_spinner.update(status=f"{prefix} – {step}")
            if not progress_console:
                return
            message = f"{prefix} – {step}"
            if color:
                progress_console.print(message, style="dim")
            else:
                progress_console.print(message)

        return _report

    def start_checks_progress(total: int) -> None:
        nonlocal checks_progress, checks_task_id
        if not progress_console or total <= 0:
            return
        checks_progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            BarColumn(bar_width=40),
            TextColumn("{task.completed}/{task.total} checks", justify="right"),
            TimeElapsedColumn(),
            console=progress_console,
            transient=True,
        )
        checks_progress.start()
        checks_task_id = checks_progress.add_task("Running checks", total=total)

    def stop_checks_progress() -> None:
        nonlocal checks_progress, checks_task_id
        if checks_progress is not None:
            checks_progress.stop()
        checks_progress = None
        checks_task_id = None

    def update_checks_progress(completed: int, total: int) -> None:
        if checks_progress is None or checks_task_id is None:
            return
        checks_progress.update(checks_task_id, completed=completed, total=total)
    check_classes = list(iter_local_checks())
    if plugins:
        check_classes += list(iter_entrypoint_checks())

    if tech:
        check_classes = [c for c in check_classes if getattr(c, "meta").tech in set(tech)]
    if include:
        check_classes = [c for c in check_classes if any(s in getattr(c, "meta").id for s in include)]
    if exclude:
        check_classes = [c for c in check_classes if not any(s in getattr(c, "meta").id for s in exclude)]

    emit_progress(f"Selected {len(check_classes)} check(s) after applying filters.")

    if list_checks:
        if not check_classes:
            console.print("[yellow]No checks matched the requested filters.[/]")
        else:
            display_console = Console(force_terminal=color, no_color=not color)
            table = Table(
                title="AuditX Checks",
                title_style="bold cyan" if color else "",
                show_lines=True,
                box=box.SQUARE,
            )
            table.add_column("ID", style="bold")
            table.add_column("Name")
            table.add_column("Tech")
            table.add_column("Severity")
            for cls in sorted(check_classes, key=lambda klass: klass.meta.id):
                meta = cls.meta
                severity_value = meta.severity.value if isinstance(meta.severity, Severity) else str(meta.severity)
                table.add_row(meta.id, meta.name, meta.tech, severity_value)
            display_console.print(table)
            console.print("[dim]Use --include <id-fragment> to run a subset of these checks.[/]")
        stop_status_spinner()
        stop_checks_progress()
        raise typer.Exit(code=0)

    if not check_classes:
        if include:
            console.print("[yellow]No checks matched the requested --include filters; skipping provider collection.[/]")
        elif any((tech, exclude)):
            console.print("[yellow]No checks matched the requested filters; skipping provider collection.[/]")
        else:
            console.print("[yellow]No checks available to run; skipping provider collection.[/]")
        stop_status_spinner()
        stop_checks_progress()
        raise typer.Exit(code=0)

    # Load & resolve config
    emit_progress("Loading configuration...")
    cfg_raw = cfg.load_project_config(explicit_files=config_files or None)
    cfg_raw = cfg.merge_overrides(cfg_raw, vars_file=vars_file, set_kv=set_kv, env=os.environ)
    cfg_resolved = cfg.resolve_secrets(cfg_raw, ask=ask_secrets)
    cfg_resolved = _ensure_config(cfg_resolved)
    emit_progress("Configuration loaded.")

    # Collect facts per selected tech (or all configured techs if none specified)
    store = FactStore(ttl=(facts_ttl or None), persisted_path=facts_cache)
    store.load()
    if tech:
        selected = set(tech)
    else:
        selected = registered_techs().union(set(cfg_resolved.keys()))
    for t in selected:
        params = cfg_resolved.get(t, {})
        emit_progress(f"Collecting facts for '{t}'...")
        reporter = make_fact_progress(t) if progress else None
        collect_facts(t, params, store, reporter=reporter)
    if selected:
        emit_progress("Fact collection complete.")

    ctx = RunContext(tech_filter=set(tech), config=cfg_resolved, env=dict(**os.environ), facts=store)

    emit_progress(f"Running {len(check_classes)} check(s) (parallel={parallel}).")
    stop_status_spinner()
    if progress:
        start_checks_progress(len(check_classes))

    def on_check_progress(done: int, total: int) -> None:
        update_checks_progress(done, total)

    results = run_all(check_classes, ctx, parallel=parallel, on_progress=on_check_progress if progress else None)
    stop_checks_progress()
    emit_progress("Checks execution finished.")

    if progress:
        emit_progress("Formatting report...")

    elapsed = time.perf_counter() - start_time
    finished_at = started_at + timedelta(seconds=elapsed)
    status_counts = Counter(result.status for result in results)
    ordered_statuses = [Status.PASS, Status.WARN, Status.FAIL, Status.SKIP, Status.ERROR]
    summary_parts = [
        f"{status_counts.get(status, 0)} {status.value}"
        for status in ordered_statuses
        if status_counts.get(status, 0) > 0
    ]
    summary_text = ", ".join(summary_parts) if summary_parts else "No checks executed"

    if format == "json":
        data = to_json(results)
    elif format == "md":
        data = to_markdown(results)
    elif format == "html":
        command_line = " ".join(shlex.quote(arg) for arg in sys.argv)
        metadata_entries: list[tuple[str, str]] = [
            ("Command", command_line),
            ("Started", started_at.isoformat(timespec="seconds")),
            ("Finished", finished_at.isoformat(timespec="seconds")),
            ("Duration", f"{elapsed:.2f} s"),
            ("Parallel", "Yes" if parallel else "No"),
            ("Output format", format),
            ("Output target", str(output) if output else "STDOUT"),
            ("Tech filter", ", ".join(tech) if tech else "All"),
        ]
        if include:
            metadata_entries.append(("Include filter", ", ".join(include)))
        if exclude:
            metadata_entries.append(("Exclude filter", ", ".join(exclude)))
        metadata_entries.append(("Checks executed", str(len(results))))
        metadata_entries.append(("Status summary", summary_text))
        data = to_html(results, metadata=metadata_entries)
    else:
        display_console = Console(force_terminal=color, no_color=not color)
        table = Table(
            title="AuditX Report",
            title_style="bold cyan" if color else "",
            show_lines=True,
            box=box.SQUARE,
        )
        table.add_column("Status")
        table.add_column("ID")
        table.add_column("Tech")
        table.add_column("Severity")
        table.add_column("Summary")
        table.add_column("Details", overflow="fold")
        status_styles = {
            Status.PASS: "green",
            Status.FAIL: "bold red",
            Status.WARN: "yellow",
            Status.SKIP: "dim",
            Status.ERROR: "bold magenta",
        }
        severity_styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }
        for r in results:
            status_value = r.status.value if isinstance(r.status, Status) else str(r.status)
            severity_value = r.meta.severity.value if isinstance(r.meta.severity, Severity) else str(r.meta.severity)
            status_cell = Text(status_value)
            severity_cell = Text(severity_value)
            if color:
                status_style = status_styles.get(r.status)
                if status_style:
                    status_cell.stylize(status_style)
                severity_style = severity_styles.get(r.meta.severity)
                if severity_style:
                    severity_cell.stylize(severity_style)
            summary_cell = Text(r.summary)
            details_lines: list[str] = []
            if r.explanation:
                details_lines.append(r.explanation)
            if r.remediation and r.remediation != r.explanation:
                details_lines.append(f"Remediation: {r.remediation}")
            details_text = Text("\n".join(details_lines)) if details_lines else Text("-")
            table.add_row(status_cell, r.meta.id, r.meta.tech, severity_cell, summary_cell, details_text)
        display_console.print(table)

        data = None

    if data is not None:
        if output:
            output.write_text(data)
            console.print(f"Wrote report to {output}")
            emit_progress(f"Report written to {output}")
        else:
            typer.echo(data)

    if progress_console:
        emit_progress(f"Summary: {summary_text}")
        stop_status_spinner()

    if show_duration:
        console.print(f"Elapsed time: {elapsed:.2f}s", style="dim")


@app.command()
def facts(
    tech: list[str] = typer.Option([], "--tech", help="Technologies to collect (defaults to configured ones)"),
    format: str = typer.Option("table", help="Output format: table|json"),
    output: Optional[Path] = typer.Option(None, help="Write facts to file instead of STDOUT"),
    config_files: list[Path] = typer.Option(
        [],
        "--config",
        help="Configuration file(s) to load after defaults (can be passed multiple times)",
    ),
    vars_file: Optional[Path] = typer.Option(None, "--vars-file", help="YAML overrides with secrets"),
    set_kv: list[str] = typer.Option([], "--set", help="Override key=val (deep)"),
    ask_secrets: bool = typer.Option(False, "--ask-secrets", help="Prompt for missing secrets"),
    facts_cache: Optional[Path] = typer.Option(None, "--facts-cache", help="Persist facts to this JSON file"),
    facts_ttl: int = typer.Option(0, "--facts-ttl", help="Seconds; 0 = no TTL"),
    color: bool = typer.Option(True, "--color/--no-color", help="Colorize table output"),
):
    """Collect and display raw facts returned by providers."""
    cfg_raw = cfg.load_project_config(explicit_files=config_files or None)
    cfg_raw = cfg.merge_overrides(cfg_raw, vars_file=vars_file, set_kv=set_kv, env=os.environ)
    cfg_resolved = cfg.resolve_secrets(cfg_raw, ask=ask_secrets)

    store = FactStore(ttl=(facts_ttl or None), persisted_path=facts_cache)
    store.load()

    if tech:
        selected = set(tech)
    else:
        selected = registered_techs().union(set(cfg_resolved.keys()))
    if not selected:
        console.print("[yellow]No technologies selected or configured.[/]")
        raise typer.Exit(code=1)

    for t in sorted(selected):
        params = cfg_resolved.get(t, {})
        collect_facts(t, params, store)

    store.save()

    payload = {t: store.data.get(t, {}) for t in sorted(selected)}

    if format == "json":
        text = json.dumps(payload, indent=2, default=str)
        if output:
            output.write_text(text)
            console.print(f"Wrote facts to {output}")
        else:
            typer.echo(text)
        return

    display_console = Console(force_terminal=color, no_color=not color)
    table = Table(
        title="AuditX Facts",
        title_style="bold cyan" if color else "",
        show_lines=True,
        box=box.SQUARE,
        expand=False,
        pad_edge=False,
    )
    table.add_column("Tech", style="bold", no_wrap=True)
    table.add_column("Fact", style="cyan", overflow="fold", max_width=32)
    table.add_column("Value", overflow="fold", ratio=1)

    for tech_name, facts in payload.items():
        if not facts:
            table.add_row(tech_name, "-", "-")
            continue
        for key, value in sorted(facts.items()):
            display_value = _summarize_fact_value(value)
            if isinstance(display_value, str):
                table.add_row(tech_name, key, display_value)
            else:
                table.add_row(tech_name, key, Pretty(display_value))

    display_console.print(table)

@app.command()
def docs(
    tech: list[str] = typer.Option([], "--tech", help="Technologies to include (e.g., linux, zabbix, mysql)"),
    include: list[str] = typer.Option([], "--include", help="Only document checks whose id contains these substrings"),
    exclude: list[str] = typer.Option([], "--exclude", help="Skip checks whose id contains these substrings"),
    format: str = typer.Option("table", "--format", help="Output format: markdown|table|html"),
    output: Optional[Path] = typer.Option(None, help="Write generated docs to this file instead of STDOUT"),
    config_files: list[Path] = typer.Option(
        [],
        "--config",
        help="Configuration file(s) to load after defaults (can be passed multiple times)",
    ),
):
    """Generate documentation from discovered checks (metadata and inputs)."""
    cfg.load_project_config(explicit_files=config_files or None)

    checks = list(iter_local_checks()) + list(iter_entrypoint_checks())
    if tech:
        allowed = set(tech)
        checks = [c for c in checks if c.meta.tech in allowed]
    if include:
        checks = [c for c in checks if any(substr in c.meta.id for substr in include)]
    if exclude:
        checks = [c for c in checks if not any(substr in c.meta.id for substr in exclude)]
    fmt = format.lower().strip()

    entries: list[dict[str, Any]] = []
    for c in checks:
        meta = c.meta
        tags = sorted(meta.tags)
        entries.append(
            {
                "id": meta.id,
                "name": meta.name,
                "tech": meta.tech,
                "severity": meta.severity.value if isinstance(meta.severity, Severity) else str(meta.severity),
                "version": meta.version,
                "tags": tags,
                "description": meta.description,
                "explanation": meta.explanation,
                "remediation": meta.remediation,
                "inputs": [dict(spec) for spec in meta.inputs],
                "requires_privileges": meta.requires_privileges,
            }
        )

    if fmt in {"markdown", "md"}:
        lines = ["# AuditX – Checks Documentation"]
        for entry in entries:
            inputs_block = "\n".join(
                f"- `{spec.get('key','')}`{' (secret)' if spec.get('secret') else ''}{' – required' if spec.get('required') else ''}: {spec.get('description','')}"
                for spec in entry["inputs"]
            )
            lines += [
                f"\n## {entry['id']}",
                f"**Name:** {entry['name']}",
                f"**Tech:** {entry['tech']} | **Severity:** {entry['severity']}",
                f"**Version:** {entry['version']}",
                f"**Tags:** {', '.join(entry['tags']) or '-'}",
                f"**Description:** {entry['description']}",
                f"**Explanation:** {entry['explanation'] or '-'}",
                f"**Remediation:** {entry['remediation'] or '-'}",
                "\n### Inputs\n" + (inputs_block or "- None"),
            ]
        md = "\n".join(lines)
        if output:
            output.write_text(md)
            console.print(f"Wrote docs to {output}")
        else:
            typer.echo(md)
        return

    if fmt == "html":
        html_output = docs_to_html(entries)
        if output:
            output.write_text(html_output)
            console.print(f"Wrote docs to {output}")
        else:
            typer.echo(html_output)
        return

    if fmt == "table":
        table = Table(
            title="AuditX Checks",
            title_style="bold cyan",
            show_lines=True,
            box=box.SQUARE,
        )
        table.add_column("ID", style="bold")
        table.add_column("Name")
        table.add_column("Tech")
        table.add_column("Severity")
        table.add_column("Tags")
        table.add_column("Description")
        table.add_column("Explanation", overflow="fold")
        table.add_column("Remediation", overflow="fold")

        for entry in entries:
            tags = ", ".join(entry["tags"]) or "-"
            table.add_row(
                entry["id"],
                entry["name"],
                entry["tech"],
                entry["severity"],
                tags,
                entry["description"],
                entry["explanation"] or "-",
                entry["remediation"] or "-",
            )

        display = console if output is None else Console(record=True)
        display.print(table)
        if output:
            output.write_text(display.export_text())
            console.print(f"Wrote docs to {output}")
        return

    if fmt == "json":
        payload = [
            {
                "id": entry["id"],
                "name": entry["name"],
                "tech": entry["tech"],
                "severity": entry["severity"],
                "version": entry["version"],
                "tags": entry["tags"],
                "description": entry["description"],
                "explanation": entry["explanation"],
                "remediation": entry["remediation"],
                "requires_privileges": entry["requires_privileges"],
                "inputs": entry["inputs"],
            }
            for entry in entries
        ]
        text = json.dumps(payload, indent=2, default=str)
        if output:
            output.write_text(text)
            console.print(f"Wrote docs to {output}")
        else:
            typer.echo(text)
        return

    raise typer.BadParameter("--format must be one of: markdown, table, html, json", param_hint="--format")

if __name__ == "__main__":
    app()
