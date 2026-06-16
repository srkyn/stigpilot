"""Command line interface for STIGPilot."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Optional

import typer
from rich.columns import Columns
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .config import CONFIG_EXAMPLE, StigPilotConfig, load_config
from .diff import compare_documents, duplicate_keys
from .exporters import (
    github_issue_markdown,
    remediation_draft_markdown,
    write_backlog_csv,
    write_changes_json,
    write_controls_csv,
    write_controls_json,
    write_jira_csv,
    write_servicenow_csv,
    write_ticket_csv,
)
from .parser import StigParseError, parse_stig
from .reports import change_brief, change_summary_counts, evidence_checklist, filter_by_severity, html_change_brief, impact_label, manager_summary_report, priority_changes, single_stig_brief, write_text_report
from .taxonomy import suggested_owner

app = typer.Typer(
    help="Turn DISA STIG XCCDF release changes into briefs, backlogs, evidence checklists, and ticket-ready exports.",
    no_args_is_help=True,
)
console = Console(no_color=not sys.stdout.isatty())
_NO_COLOR = not sys.stdout.isatty()
VALID_IMPACTS = {
    "high_priority_review",
    "implementation_change_likely",
    "evidence_update_likely",
    "review_recommended",
    "no_action_likely",
}
PACKET_COMMON_FILES = (
    "START_HERE.md",
    "change-brief.md",
    "changes.json",
    "remediation-backlog.csv",
    "evidence-checklist.md",
    "jira-import.csv",
    "servicenow-import.csv",
    "github-issues.md",
)
PACKET_PYTHON_EXTRA_FILES = (
    "change-brief.html",
    "manager-summary.md",
    "remediation-drafts.md",
)
SEVERITY_COLORS = {
    "high": "bold red",
    "HIGH": "bold red",
    "high_priority_review": "bold red",
    "High-priority review": "bold red",
    "medium": "bold yellow",
    "MEDIUM": "bold yellow",
    "implementation_change_likely": "yellow",
    "Implementation change likely": "yellow",
    "evidence_update_likely": "yellow",
    "Evidence update likely": "yellow",
    "low": "dim cyan",
    "LOW": "dim cyan",
    "review_recommended": "cyan",
    "Review recommended": "cyan",
    "no_action_likely": "dim",
    "No action likely": "dim",
}


@app.callback()
def main(
    ctx: typer.Context,
    no_color: bool = typer.Option(False, "--no-color", help="Disable terminal colors and Rich styling."),
) -> None:
    """Configure global CLI display settings."""

    global console, _NO_COLOR
    _NO_COLOR = no_color or not sys.stdout.isatty()
    console = Console(no_color=_NO_COLOR)
    if ctx.invoked_subcommand and not ctx.resilient_parsing:
        _print_header()


def colorize_severity(text: object) -> str:
    """Return a Rich markup string for severity or impact text."""

    value = str(text or "")
    style = SEVERITY_COLORS.get(value, "")
    if not style:
        style = SEVERITY_COLORS.get(value.lower(), "")
    return f"[{style}]{value}[/{style}]" if style and not _NO_COLOR else value


def _print_header() -> None:
    console.print(
        Panel(
            f"[bold blue]STIGPilot[/bold blue]  [dim]v{__version__}[/dim]   [dim]STIG change intelligence[/dim]",
            border_style="blue",
            padding=(0, 2),
        )
    )


def _load_config(config_path: Path | None) -> StigPilotConfig | None:
    try:
        return load_config(config_path)
    except ValueError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(1) from exc


def _load(path: Path, config: StigPilotConfig | None = None):
    try:
        if sys.stdout.isatty() and not _NO_COLOR:
            try:
                total_count = max(1, len(re.findall(rb"<[^/!?][^>]*\bRule\b", path.read_bytes())))
            except OSError:
                total_count = 1
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task("Parsing STIG controls...", total=total_count)
                document = parse_stig(path, config, progress_advance=lambda: progress.advance(task))
        else:
            document = parse_stig(path, config)
    except StigParseError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc
    if not document.controls:
        console.print(f"[yellow]Warning:[/yellow] No Rule controls found in {path}")
    return document


def _prefer_repo_relative_source(document, repo_root: Path) -> None:
    """Keep bundled demo metadata portable when sample outputs are regenerated."""

    try:
        document.source_file = str(Path(document.source_file).resolve().relative_to(repo_root))
    except (OSError, ValueError):
        return


def _safe_write(action, output: Path, label: str) -> None:
    try:
        action()
    except OSError as exc:
        console.print(f"[red]Output error:[/red] could not write {label} to {output}: {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Wrote {label}:[/green] {output}")


def _warn_same_inputs(old_xml: Path, new_xml: Path, old_doc, new_doc) -> None:
    try:
        if old_xml.resolve() == new_xml.resolve() or old_xml.read_bytes() == new_xml.read_bytes():
            console.print("[yellow]Warning:[/yellow] old and new inputs appear to be the same file or same content.")
            return
    except OSError:
        return
    if old_doc.version == new_doc.version and old_doc.release == new_doc.release:
        console.print("[yellow]Warning:[/yellow] old and new STIG metadata appear to describe the same release.")


def _print_change_summary(changes, outputs: list[Path]) -> None:
    counts = change_summary_counts(changes)
    border_style = "red" if counts["high_priority_review"] else "yellow" if counts["implementation_change_likely"] or counts["evidence_update_likely"] else "green"
    summary = (
        f"[dim]{counts['total']} change(s) detected. "
        f"{counts['high_priority_review']} high-priority, "
        f"{counts['implementation_change_likely']} implementation-likely, "
        f"{counts['evidence_update_likely']} evidence-update-likely.[/dim]"
    )
    console.print(Panel(summary, title="[bold]Change Summary[/bold]", border_style=border_style))
    if _NO_COLOR:
        console.print("-" * 72)
    else:
        console.rule(style="dim")
    panels = []
    for label, key in (
        ("Total", "total"),
        ("Added", "added"),
        ("Removed", "removed"),
        ("Modified", "modified"),
        ("Severity", "severity_changed"),
        ("High", "high_priority_review"),
        ("Impl", "implementation_change_likely"),
        ("Evidence", "evidence_update_likely"),
    ):
        count = counts[key]
        count_text = _metric_count_markup(key, count)
        panels.append(Panel(count_text, title=f"[dim]{label}[/dim]", width=22, border_style="dim"))
    console.print(Columns(panels, equal=True, expand=True))
    priority = [change for change in changes if change.impact in {"high_priority_review", "implementation_change_likely", "evidence_update_likely"}][:5]
    if priority:
        console.print("[bold blue]Priority actions[/bold blue]")
        for change in priority:
            control = change.current_control
            title = f"{change.vuln_id or (control.vuln_id if control else '')} - {(control.title if control else '') or 'Untitled'}"
            owner = suggested_owner(control)
            body = f"[dim]{colorize_severity(impact_label(change.impact))} · {owner}[/dim]\n{change.reason}"
            console.print(Panel(body, title=f"[bold]{title}[/bold]", border_style=_impact_border(change.impact)))
    if outputs:
        console.print("[bold]Written files:[/bold]")
        for output in outputs:
            console.print(f"- {output}")


def _metric_count_markup(key: str, count: int) -> str:
    if count == 0:
        return "[dim]0[/dim]" if not _NO_COLOR else "0"
    if key == "high_priority_review":
        return f"[bold red]{count}[/bold red]" if not _NO_COLOR else str(count)
    if key in {"implementation_change_likely", "evidence_update_likely", "removed", "severity_changed"}:
        return f"[bold yellow]{count}[/bold yellow]" if not _NO_COLOR else str(count)
    if key == "added":
        return f"[bold blue]{count}[/bold blue]" if not _NO_COLOR else str(count)
    return f"[bold]{count}[/bold]" if not _NO_COLOR else str(count)


def _impact_border(impact: str) -> str:
    if impact == "high_priority_review":
        return "red"
    if impact in {"implementation_change_likely", "evidence_update_likely"}:
        return "yellow"
    return "cyan"




def _filter_changes(
    changes,
    impact_filter: str | None = None,
    owner_filter: str | None = None,
    config: StigPilotConfig | None = None,
):
    filtered = list(changes)
    if impact_filter:
        impact = impact_filter.strip()
        if impact not in VALID_IMPACTS:
            console.print(
                "[red]Filter error:[/red] --impact must be one of "
                + ", ".join(sorted(VALID_IMPACTS))
            )
            raise typer.Exit(1)
        filtered = [change for change in filtered if change.impact == impact]
    if owner_filter:
        owner = owner_filter.strip().casefold()
        filtered = [
            change
            for change in filtered
            if suggested_owner(change.current_control, config).casefold() == owner
        ]
    return filtered


def _packet_start_here(old_doc, new_doc, changes, outputs: dict[str, Path], config: StigPilotConfig | None = None) -> str:
    counts = change_summary_counts(changes)
    top_actions = priority_changes(changes)[:5]
    output_dir = next(iter(outputs.values())).parent if outputs else Path(".")

    lines = [
        "# STIGPilot Packet",
        "",
        "Start here if someone handed you this folder and you need to know what matters.",
        "",
        "## Summary",
        "",
        f"- Old controls: {len(old_doc.controls)}",
        f"- New controls: {len(new_doc.controls)}",
        f"- Total changes: {counts['total']}",
        f"- Added controls: {counts['added']}",
        f"- Removed controls: {counts['removed']}",
        f"- Modified controls: {counts['modified']}",
        f"- Severity changes: {counts['severity_changed']}",
        f"- High-priority review: {counts['high_priority_review']}",
        f"- Implementation change likely: {counts['implementation_change_likely']}",
        f"- Evidence update likely: {counts['evidence_update_likely']}",
        "",
        "## Open These First",
        "",
        "1. `change-brief.md` for analyst triage and priority actions.",
        "2. `manager-summary.md` for a short leadership readout.",
        "3. `remediation-backlog.csv` for backlog grooming or ticket prep.",
        "4. `evidence-checklist.md` when validation steps or evidence requests need refresh.",
        "",
        "## Next 15 Minutes",
        "",
        "| Role | Do this first |",
        "| --- | --- |",
        "| Security analyst | Read `change-brief.md`, then mark the high-priority and implementation-likely rows in `remediation-backlog.csv`. |",
        "| Sysadmin or engineer | Filter `remediation-backlog.csv` by your owner group, then review changed fix text before reusing old implementation notes. |",
        "| GRC or evidence owner | Open `evidence-checklist.md` and refresh requests for controls marked evidence update likely. |",
        "| Manager or lead | Read `manager-summary.md`, then use the owner impact table to decide which team needs the first review block. |",
        "",
        "## File Map",
        "",
        "| File | Use it for |",
        "| --- | --- |",
    ]

    file_purposes = {
        "Change brief": "Analyst-ready change summary and detailed changed-control table.",
        "HTML change brief": "Self-contained browser-friendly version of the change brief.",
        "Changes JSON": "Machine-readable export for local automation or review.",
        "Manager summary": "Short readout for managers and team leads.",
        "Remediation backlog": "CSV backlog for triage, ownership, notes, and status tracking.",
        "Evidence checklist": "Owner-grouped evidence requests and validation metadata.",
        "Jira import": "Local CSV shaped for Jira import review.",
        "ServiceNow import": "Local CSV shaped for ServiceNow import review.",
        "GitHub issues": "Copy-paste-ready Markdown issue drafts.",
        "Remediation drafts": "Review-only implementation notes. STIGPilot does not apply changes.",
    }

    for name, path in outputs.items():
        try:
            display_path = path.relative_to(output_dir).as_posix()
        except ValueError:
            display_path = path.name
        lines.append(f"| `{display_path}` | {file_purposes.get(name, 'Generated STIGPilot artifact.')} |")

    lines.extend(["", "## Top Actions", ""])
    if not top_actions:
        lines.append("- No changes were detected in this packet.")
    else:
        for index, change in enumerate(top_actions, start=1):
            control = change.current_control
            control_id = change.vuln_id or change.rule_id or (control.vuln_id if control else "") or (control.rule_id if control else "") or "unknown-control"
            title = control.title if control else "Removed control"
            owner = suggested_owner(control, config)
            lines.append(
                f"{index}. `{control_id}` - {title} ({impact_label(change.impact)}, {owner}): {change.reason}"
            )

    lines.extend(
        [
            "",
            "## Reminder",
            "",
            "STIGPilot is a local workflow helper for change triage, remediation planning, evidence preparation, and ticket exports. It does not scan systems, validate compliance, or replace official DISA tooling.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _write_comparison_packet(old_doc, new_doc, changes, out: Path, config: StigPilotConfig | None = None) -> dict[str, Path]:
    out.mkdir(parents=True, exist_ok=True)
    outputs = {
        "Start here": out / "START_HERE.md",
        "Change brief": out / "change-brief.md",
        "HTML change brief": out / "change-brief.html",
        "Changes JSON": out / "changes.json",
        "Manager summary": out / "manager-summary.md",
        "Remediation backlog": out / "remediation-backlog.csv",
        "Evidence checklist": out / "evidence-checklist.md",
        "Jira import": out / "jira-import.csv",
        "ServiceNow import": out / "servicenow-import.csv",
        "GitHub issues": out / "github-issues.md",
        "Remediation drafts": out / "remediation-drafts.md",
    }
    content_outputs = {name: path for name, path in outputs.items() if name != "Start here"}
    write_text_report(outputs["Change brief"], change_brief(old_doc, new_doc, changes, config))
    write_text_report(outputs["HTML change brief"], html_change_brief(old_doc, new_doc, changes, config))
    write_changes_json(changes, outputs["Changes JSON"], old_doc, new_doc, config)
    write_text_report(outputs["Manager summary"], manager_summary_report(old_doc, new_doc, changes, config))
    write_backlog_csv(changes, outputs["Remediation backlog"], config)
    write_text_report(outputs["Evidence checklist"], evidence_checklist(new_doc, config=config))
    write_jira_csv(changes, outputs["Jira import"], config)
    write_servicenow_csv(changes, outputs["ServiceNow import"], config)
    write_text_report(outputs["GitHub issues"], github_issue_markdown(changes, config))
    write_text_report(outputs["Remediation drafts"], remediation_draft_markdown(changes, config))
    write_text_report(outputs["Start here"], _packet_start_here(old_doc, new_doc, changes, content_outputs, config))
    return outputs


def _xml_files(directory: Path) -> list[Path]:
    return sorted(path for path in directory.rglob("*.xml") if path.is_file())


def _match_key(document, path: Path) -> str:
    basis = document.title or path.stem
    key = re.sub(r"[^a-z0-9]+", " ", basis.casefold()).strip()
    return re.sub(r"\s+", " ", key)


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return slug or "stig-comparison"


def _index_documents(documents: dict[Path, object]) -> tuple[dict[str, tuple[Path, object]], dict[str, list[Path]]]:
    index: dict[str, tuple[Path, object]] = {}
    duplicates: dict[str, list[Path]] = {}
    for path, document in documents.items():
        key = _match_key(document, path)
        if key in index:
            duplicates.setdefault(key, [index[key][0]]).append(path)
            continue
        index[key] = (path, document)
    return index, duplicates


def _portfolio_summary(
    rows: list[dict[str, object]],
    unmatched_old: list[Path],
    unmatched_new: list[Path],
    out: Path,
) -> str:
    total_changes = sum(int(row["total"]) for row in rows)
    high_priority = sum(int(row["high_priority_review"]) for row in rows)
    implementation = sum(int(row["implementation_change_likely"]) for row in rows)
    evidence = sum(int(row["evidence_update_likely"]) for row in rows)
    lines = [
        "# STIGPilot Portfolio Summary",
        "",
        "## Executive Summary",
        "",
        (
            f"{len(rows)} STIG comparison(s) were matched and analyzed. "
            f"{total_changes} total control change(s) were detected across the compared files. "
            f"{high_priority} change(s) need high-priority review, {implementation} likely need implementation review, "
            f"and {evidence} likely need refreshed evidence requests."
        ),
        "",
        "## At-a-Glance",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| STIGs compared | {len(rows)} |",
        f"| Total changes | {total_changes} |",
        f"| High-priority review | {high_priority} |",
        f"| Implementation change likely | {implementation} |",
        f"| Evidence update likely | {evidence} |",
        f"| Unmatched old files | {len(unmatched_old)} |",
        f"| Unmatched new files | {len(unmatched_new)} |",
        "",
        "## Compared STIGs",
        "",
        "| STIG | Old Controls | New Controls | Changes | High Priority | Implementation Likely | Evidence Updates | Packet |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        packet = Path(str(row["packet"])).relative_to(out)
        lines.append(
            f"| {row['title']} | {row['old_controls']} | {row['new_controls']} | {row['total']} | "
            f"{row['high_priority_review']} | {row['implementation_change_likely']} | {row['evidence_update_likely']} | "
            f"[change brief]({packet.as_posix()}/change-brief.md) |"
        )
    if unmatched_old or unmatched_new:
        lines.extend(["", "## Unmatched Files", ""])
        if unmatched_old:
            lines.append("Old-only files:")
            lines.extend(f"- `{path}`" for path in unmatched_old)
            lines.append("")
        if unmatched_new:
            lines.append("New-only files:")
            lines.extend(f"- `{path}`" for path in unmatched_new)
            lines.append("")
    lines.extend(
        [
            "",
            "## How to Use This",
            "",
            "- Open the per-STIG change brief for analyst triage.",
            "- Use each remediation backlog CSV for ticket queue grooming or imports.",
            "- Use each evidence checklist when validation procedures or evidence requests changed.",
            "- Treat this as change intelligence and planning support, not formal compliance validation.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _print_outputs_table(title: str, outputs: dict[str, Path]) -> None:
    table = Table(title=title, header_style="bold blue", border_style="dim", show_lines=False)
    table.add_column("Report")
    table.add_column("Path")
    for name, path in outputs.items():
        table.add_row(name, str(path))
    console.print(table)


@app.command()
def quickstart() -> None:
    """Show the fastest useful paths for Python and Government Mode."""

    def cmd(value: str) -> str:
        return rich_escape(value)

    console.print("[bold]Pick the path that fits your environment.[/bold]")
    console.print(
        "Keep official STIG XMLs under [cyan]stigs/<product>/<release>/[/cyan] "
        "and write reports under [cyan]output/<review-name>/[/cyan]."
    )
    console.print("")

    python_table = Table(title="Python CLI", header_style="bold blue", border_style="dim", show_lines=False)
    python_table.add_column("Goal")
    python_table.add_column("Command")
    python_table.add_row("Install for development", cmd('python -m pip install -e ".[dev]"'))
    python_table.add_row("Check local setup", cmd("stigpilot doctor"))
    python_table.add_row("Generate demo packet", cmd("stigpilot demo"))
    python_table.add_row(
        "Compare two STIG files",
        cmd("stigpilot packet stigs/chrome-windows/v2r10/old.xml stigs/chrome-windows/v2r11/new.xml --out output/chrome-review"),
    )
    python_table.add_row(
        "Archive handoff packet",
        cmd("stigpilot archive-output output/chrome-review --out output/chrome-review.zip"),
    )

    gov_table = Table(title="Government Mode", header_style="bold green", border_style="dim", show_lines=False)
    gov_table.add_column("Goal")
    gov_table.add_column("Command")
    gov_table.add_row("Check PowerShell setup", cmd(r".\tools\STIGPilot-Gov.ps1 -Command doctor"))
    gov_table.add_row(
        "Generate local packet",
        cmd(
            r".\tools\STIGPilot-Gov.ps1 -Command packet -Old stigs\chrome-windows\v2r10\old.xml "
            r"-New stigs\chrome-windows\v2r11\new.xml -OutDir output\chrome-gov"
        ),
    )
    gov_table.add_row(
        "Use launcher",
        cmd(
            r"tools\STIGPilot.cmd -Command packet -Old stigs\chrome-windows\v2r10\old.xml "
            r"-New stigs\chrome-windows\v2r11\new.xml -OutDir output\chrome-gov"
        ),
    )
    gov_table.add_row(
        "Archive handoff packet",
        cmd(r".\tools\STIGPilot-Gov.ps1 -Command archive -OutDir output\chrome-gov -Zip output\chrome-gov.zip"),
    )

    console.print(python_table)
    console.print(gov_table)
    console.print("[bold]Start here:[/bold] run [cyan]stigpilot demo[/cyan], then open [cyan]output/demo/START_HERE.md[/cyan].")
    console.print("For real files, see [cyan]docs/where-to-put-stigs.md[/cyan].")
    console.print("Government Mode uses built-in PowerShell/.NET only and is intentionally smaller than the Python CLI.")


def _print_chrome_missing_message(input_dir: Path, sample_old: Path, sample_new: Path) -> None:
    console.print("[yellow]Official Chrome STIG files were not found.[/yellow]")
    console.print(f"Missing expected files under: {input_dir}")
    console.print("- old.xml  (Google Chrome Current Windows STIG V2R10 XCCDF)")
    console.print("- new.xml  (Google Chrome Current Windows STIG V2R11 XCCDF)")
    console.print("")
    console.print("Download official public STIG ZIPs from DoD Cyber Exchange:")
    console.print("- https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R10_STIG.zip")
    console.print("- https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R11_STIG.zip")
    console.print("")
    console.print("Extract the XCCDF XML files and place them as:")
    console.print(f"- {input_dir / 'old.xml'}")
    console.print(f"- {input_dir / 'new.xml'}")
    console.print("")
    console.print("For now, STIGPilot will run the bundled sanitized Chrome sample:")
    console.print(f"- {sample_old}")
    console.print(f"- {sample_new}")


@app.command()
def parse(
    input_xml: Path = typer.Argument(..., exists=True, readable=True, help="STIG XCCDF/XML input file."),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Write parsed controls to CSV."),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write parsed controls to JSON."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Parse a STIG and export normalized controls."""

    config = _load_config(config_path)
    document = _load(input_xml, config)
    if csv_out:
        _safe_write(lambda: write_controls_csv(document, csv_out), csv_out, "CSV")
    if json_out:
        _safe_write(lambda: write_controls_json(document, json_out), json_out, "JSON")
    if not csv_out and not json_out:
        console.print(f"Parsed {len(document.controls)} controls from {input_xml}")


@app.command()
def brief(
    input_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Markdown report output path."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Optional severity filter, such as high."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate a readable Markdown brief from one STIG file."""

    config = _load_config(config_path)
    document = _load(input_xml, config)
    _safe_write(lambda: write_text_report(out, single_stig_brief(document, severity, config)), out, "brief")


@app.command()
def diff(
    old_xml: Path = typer.Argument(..., exists=True, readable=True),
    new_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Markdown change brief output path."),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Remediation backlog CSV output path."),
    jira_csv: Optional[Path] = typer.Option(None, "--jira-csv", help="Jira-friendly CSV output path."),
    servicenow_csv: Optional[Path] = typer.Option(None, "--servicenow-csv", help="ServiceNow-friendly CSV output path."),
    github_md: Optional[Path] = typer.Option(None, "--github-md", help="GitHub issue draft Markdown output path."),
    drafts_md: Optional[Path] = typer.Option(None, "--drafts-md", help="Review-only remediation draft Markdown output path."),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Machine-readable changes JSON output path."),
    impact_filter: Optional[str] = typer.Option(None, "--impact", help="Only include one impact category, such as high_priority_review."),
    owner_filter: Optional[str] = typer.Option(None, "--owner", help='Only include changes for one suggested owner, such as "Endpoint/Windows Admin".'),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Compare two STIG versions and generate a change brief."""

    config = _load_config(config_path)
    old_doc = _load(old_xml, config)
    new_doc = _load(new_xml, config)
    _warn_same_inputs(old_xml, new_xml, old_doc, new_doc)
    for source_name, duplicates in (("old", duplicate_keys(old_doc.controls)), ("new", duplicate_keys(new_doc.controls))):
        if duplicates:
            console.print(f"[yellow]Warning:[/yellow] duplicate stable keys in {source_name} file: {duplicates}")
    all_changes = compare_documents(old_doc, new_doc)
    changes = _filter_changes(all_changes, impact_filter, owner_filter, config)
    outputs = [out]
    _safe_write(lambda: write_text_report(out, change_brief(old_doc, new_doc, changes, config)), out, "change brief")
    if csv_out:
        _safe_write(lambda: write_backlog_csv(changes, csv_out, config), csv_out, "backlog CSV")
        outputs.append(csv_out)
    if jira_csv:
        _safe_write(lambda: write_jira_csv(changes, jira_csv, config), jira_csv, "Jira CSV")
        outputs.append(jira_csv)
    if servicenow_csv:
        _safe_write(lambda: write_servicenow_csv(changes, servicenow_csv, config), servicenow_csv, "ServiceNow CSV")
        outputs.append(servicenow_csv)
    if github_md:
        _safe_write(lambda: write_text_report(github_md, github_issue_markdown(changes, config)), github_md, "GitHub issue drafts")
        outputs.append(github_md)
    if drafts_md:
        _safe_write(lambda: write_text_report(drafts_md, remediation_draft_markdown(changes, config)), drafts_md, "remediation drafts")
        outputs.append(drafts_md)
    if json_out:
        _safe_write(lambda: write_changes_json(changes, json_out, old_doc, new_doc, config), json_out, "changes JSON")
        outputs.append(json_out)
    _print_change_summary(changes, outputs)


@app.command()
def manager(
    old_xml: Path = typer.Argument(..., exists=True, readable=True),
    new_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Manager-facing Markdown summary output path."),
    impact_filter: Optional[str] = typer.Option(None, "--impact", help="Only include one impact category, such as high_priority_review."),
    owner_filter: Optional[str] = typer.Option(None, "--owner", help='Only include changes for one suggested owner, such as "Endpoint/Windows Admin".'),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate a concise manager-facing summary for a STIG version comparison."""

    config = _load_config(config_path)
    old_doc = _load(old_xml, config)
    new_doc = _load(new_xml, config)
    _warn_same_inputs(old_xml, new_xml, old_doc, new_doc)
    all_changes = compare_documents(old_doc, new_doc)
    changes = _filter_changes(all_changes, impact_filter, owner_filter, config)
    _safe_write(lambda: write_text_report(out, manager_summary_report(old_doc, new_doc, changes, config)), out, "manager summary")
    _print_change_summary(changes, [out])


@app.command()
def packet(
    old_xml: Path = typer.Argument(..., exists=True, readable=True, help="Old STIG XCCDF/XML file."),
    new_xml: Path = typer.Argument(..., exists=True, readable=True, help="New STIG XCCDF/XML file."),
    out: Path = typer.Option(Path("output/packet"), "--out", help="Directory for the generated comparison packet."),
    impact_filter: Optional[str] = typer.Option(None, "--impact", help="Only include one impact category, such as high_priority_review."),
    owner_filter: Optional[str] = typer.Option(None, "--owner", help='Only include changes for one suggested owner, such as "Endpoint/Windows Admin".'),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate a complete local workflow packet for one STIG comparison."""

    config = _load_config(config_path)
    old_doc = _load(old_xml, config)
    new_doc = _load(new_xml, config)
    _warn_same_inputs(old_xml, new_xml, old_doc, new_doc)
    for source_name, duplicates in (("old", duplicate_keys(old_doc.controls)), ("new", duplicate_keys(new_doc.controls))):
        if duplicates:
            console.print(f"[yellow]Warning:[/yellow] duplicate stable keys in {source_name} file: {duplicates}")
    all_changes = compare_documents(old_doc, new_doc)
    changes = _filter_changes(all_changes, impact_filter, owner_filter, config)
    outputs = _write_comparison_packet(old_doc, new_doc, changes, out, config)
    _print_outputs_table("STIGPilot Packet Generated", outputs)
    _print_change_summary(changes, list(outputs.values()))
    console.print(f"[bold]Start here:[/bold] {outputs['Start here']}")


@app.command("html")
def html_report(
    old_xml: Path = typer.Argument(..., exists=True, readable=True, help="Old STIG XCCDF/XML file."),
    new_xml: Path = typer.Argument(..., exists=True, readable=True, help="New STIG XCCDF/XML file."),
    out: Path = typer.Option(..., "--out", help="Self-contained HTML report output path."),
    impact_filter: Optional[str] = typer.Option(None, "--impact", help="Only include one impact category, such as high_priority_review."),
    owner_filter: Optional[str] = typer.Option(None, "--owner", help='Only include changes for one suggested owner, such as "Endpoint/Windows Admin".'),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate a self-contained HTML change brief."""

    config = _load_config(config_path)
    old_doc = _load(old_xml, config)
    new_doc = _load(new_xml, config)
    _warn_same_inputs(old_xml, new_xml, old_doc, new_doc)
    all_changes = compare_documents(old_doc, new_doc)
    changes = _filter_changes(all_changes, impact_filter, owner_filter, config)
    _safe_write(lambda: write_text_report(out, html_change_brief(old_doc, new_doc, changes, config)), out, "HTML change brief")
    _print_change_summary(changes, [out])


@app.command()
def batch(
    old_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True, readable=True, help="Directory of old STIG XCCDF/XML files."),
    new_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True, readable=True, help="Directory of new STIG XCCDF/XML files."),
    out: Path = typer.Option(Path("output/portfolio"), "--out", help="Directory for portfolio comparison reports."),
    impact_filter: Optional[str] = typer.Option(None, "--impact", help="Only include one impact category, such as high_priority_review."),
    owner_filter: Optional[str] = typer.Option(None, "--owner", help='Only include changes for one suggested owner, such as "Endpoint/Windows Admin".'),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Compare folders of old/new STIG XML files and generate a portfolio packet."""

    config = _load_config(config_path)
    old_files = _xml_files(old_dir)
    new_files = _xml_files(new_dir)
    if not old_files:
        console.print(f"[red]Error:[/red] no XML files found in old directory: {old_dir}")
        raise typer.Exit(1)
    if not new_files:
        console.print(f"[red]Error:[/red] no XML files found in new directory: {new_dir}")
        raise typer.Exit(1)

    old_docs = {path: _load(path, config) for path in old_files}
    new_docs = {path: _load(path, config) for path in new_files}
    old_index, old_duplicates = _index_documents(old_docs)
    new_index, new_duplicates = _index_documents(new_docs)
    for source_name, duplicates in (("old", old_duplicates), ("new", new_duplicates)):
        if duplicates:
            console.print(f"[yellow]Warning:[/yellow] duplicate STIG titles in {source_name} directory; using the first file for each title.")
            for key, paths in duplicates.items():
                console.print(f"- {key}: " + ", ".join(str(path) for path in paths))
    matched_keys = sorted(set(old_index) & set(new_index))
    unmatched_old = [path for key, (path, _) in old_index.items() if key not in new_index]
    unmatched_new = [path for key, (path, _) in new_index.items() if key not in old_index]

    if not matched_keys:
        console.print("[red]Error:[/red] no matching STIG titles were found between the old and new directories.")
        console.print("Tip: STIGPilot matches folder comparisons by parsed Benchmark title.")
        raise typer.Exit(1)

    out.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    all_changes = []
    for key in matched_keys:
        old_path, old_doc = old_index[key]
        new_path, new_doc = new_index[key]
        changes = compare_documents(old_doc, new_doc)
        changes = _filter_changes(changes, impact_filter, owner_filter, config)
        packet_dir = out / _slug(new_doc.title or key)
        outputs = _write_comparison_packet(old_doc, new_doc, changes, packet_dir, config)
        counts = change_summary_counts(changes)
        rows.append(
            {
                "title": new_doc.title or old_doc.title or new_path.stem,
                "old_controls": len(old_doc.controls),
                "new_controls": len(new_doc.controls),
                "packet": packet_dir,
                **counts,
            }
        )
        all_changes.extend(changes)
        console.print(f"[green]Compared:[/green] {old_path.name} -> {new_path.name}")
        _print_outputs_table("Generated Packet", outputs)

    summary_path = out / "portfolio-summary.md"
    _safe_write(lambda: write_text_report(summary_path, _portfolio_summary(rows, unmatched_old, unmatched_new, out)), summary_path, "portfolio summary")
    _print_change_summary(all_changes, [summary_path])
    if unmatched_old or unmatched_new:
        console.print("[yellow]Note:[/yellow] unmatched XML files are listed in the portfolio summary.")
    console.print(f"[bold]Start here:[/bold] {summary_path}")


@app.command()
def tickets(
    input_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Ticket-friendly CSV output path."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Optional severity filter, such as high."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate a ticket-ready export for controls."""

    config = _load_config(config_path)
    document = _load(input_xml, config)
    controls = filter_by_severity(document.controls, severity)
    _safe_write(lambda: write_ticket_csv(controls, out, config), out, "ticket CSV")


@app.command()
def evidence(
    input_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Markdown checklist output path."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Optional severity filter."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate a Markdown evidence checklist."""

    config = _load_config(config_path)
    document = _load(input_xml, config)
    _safe_write(lambda: write_text_report(out, evidence_checklist(document, severity, config)), out, "evidence checklist")


@app.command("drafts")
def drafts(
    old_xml: Path = typer.Argument(..., exists=True, readable=True),
    new_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Review-only remediation draft Markdown output path."),
    impact_filter: Optional[str] = typer.Option(None, "--impact", help="Only include one impact category, such as high_priority_review."),
    owner_filter: Optional[str] = typer.Option(None, "--owner", help='Only include changes for one suggested owner, such as "Endpoint/Windows Admin".'),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate review-only remediation draft notes without applying changes."""

    config = _load_config(config_path)
    old_doc = _load(old_xml, config)
    new_doc = _load(new_xml, config)
    _warn_same_inputs(old_xml, new_xml, old_doc, new_doc)
    changes = _filter_changes(compare_documents(old_doc, new_doc), impact_filter, owner_filter, config)
    _safe_write(lambda: write_text_report(out, remediation_draft_markdown(changes, config)), out, "remediation drafts")
    _print_change_summary(changes, [out])


@app.command()
def summary(
    input_xml: Path = typer.Argument(..., exists=True, readable=True),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Show a terminal summary for one STIG file."""

    config = _load_config(config_path)
    document = _load(input_xml, config)
    table = Table(title=document.title or "STIG Summary", header_style="bold blue", border_style="dim", show_lines=False)
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    counts: dict[str, int] = {}
    for control in document.controls:
        key = control.severity or "unspecified"
        counts[key] = counts.get(key, 0) + 1
    for severity, count in sorted(counts.items()):
        table.add_row(colorize_severity(severity), str(count))
    console.print(table)
    console.print(f"Source: {input_xml}")
    console.print(f"Version: {document.version or 'Unknown'} | Release: {document.release or 'Unknown'}")
    console.print(f"Controls: {len(document.controls)}")

    owner_table = Table(title="Suggested Owner Summary", header_style="bold blue", border_style="dim", show_lines=False)
    owner_table.add_column("Owner")
    owner_table.add_column("Controls", justify="right")
    owners: dict[str, int] = {}
    for control in document.controls:
        owner = suggested_owner(control, config)
        owners[owner] = owners.get(owner, 0) + 1
    for owner, count in sorted(owners.items()):
        owner_table.add_row(owner, str(count))
    console.print(owner_table)


@app.command()
def demo(
    out: Path = typer.Option(Path("output/demo"), "--out", help="Directory for generated demo reports."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate sample STIGPilot reports from sanitized demo fixtures."""

    root = Path(__file__).resolve().parents[1]
    old_xml = root / "examples" / "sample_input" / "old.xml"
    new_xml = root / "examples" / "sample_input" / "new.xml"
    out.mkdir(parents=True, exist_ok=True)

    config = _load_config(config_path)
    new_doc = _load(new_xml, config)
    old_doc = _load(old_xml, config)
    _prefer_repo_relative_source(new_doc, root)
    _prefer_repo_relative_source(old_doc, root)
    changes = compare_documents(old_doc, new_doc)

    outputs = {
        "Start here": out / "START_HERE.md",
        "Controls CSV": out / "controls.csv",
        "Controls JSON": out / "controls.json",
        "Brief": out / "brief.md",
        "Change brief": out / "change-brief.md",
        "HTML change brief": out / "change-brief.html",
        "Changes JSON": out / "changes.json",
        "Manager summary": out / "manager-summary.md",
        "Remediation backlog": out / "remediation-backlog.csv",
        "Evidence checklist": out / "evidence-checklist.md",
        "Jira import": out / "jira-import.csv",
        "ServiceNow import": out / "servicenow-import.csv",
        "GitHub issues": out / "github-issues.md",
        "Remediation drafts": out / "remediation-drafts.md",
    }
    comparison_outputs = {
        name: path
        for name, path in outputs.items()
        if name
        in {
            "Change brief",
            "HTML change brief",
            "Changes JSON",
            "Manager summary",
            "Remediation backlog",
            "Evidence checklist",
            "Jira import",
            "ServiceNow import",
            "GitHub issues",
            "Remediation drafts",
        }
    }
    write_controls_csv(new_doc, outputs["Controls CSV"])
    write_controls_json(new_doc, outputs["Controls JSON"])
    write_text_report(outputs["Brief"], single_stig_brief(new_doc, config=config))
    write_text_report(outputs["Change brief"], change_brief(old_doc, new_doc, changes, config))
    write_text_report(outputs["HTML change brief"], html_change_brief(old_doc, new_doc, changes, config))
    write_changes_json(changes, outputs["Changes JSON"], old_doc, new_doc, config)
    write_text_report(outputs["Manager summary"], manager_summary_report(old_doc, new_doc, changes, config))
    write_backlog_csv(changes, outputs["Remediation backlog"], config)
    write_text_report(outputs["Evidence checklist"], evidence_checklist(new_doc, config=config))
    write_jira_csv(changes, outputs["Jira import"], config)
    write_servicenow_csv(changes, outputs["ServiceNow import"], config)
    write_text_report(outputs["GitHub issues"], github_issue_markdown(changes, config))
    write_text_report(outputs["Remediation drafts"], remediation_draft_markdown(changes, config))
    write_text_report(outputs["Start here"], _packet_start_here(old_doc, new_doc, changes, comparison_outputs, config))

    table = Table(title="Demo Reports Generated", header_style="bold blue", border_style="dim", show_lines=False)
    table.add_column("Report")
    table.add_column("Path")
    for name, path in outputs.items():
        table.add_row(name, str(path))
    console.print(table)
    _print_change_summary(changes, [])
    console.print("[bold]Start here:[/bold]")
    console.print(f"- Open {outputs['Start here']}")
    console.print(f"- Open {outputs['Change brief']}")
    console.print(f"- Open {outputs['Manager summary']}")
    console.print(f"- Open {outputs['Remediation backlog']}")


@app.command("chrome-demo")
def chrome_demo(
    out: Path = typer.Option(Path("output/chrome"), "--out", help="Directory for generated Chrome demo reports."),
    input_dir: Path = typer.Option(
        Path("examples/chrome_windows_input"),
        "--input-dir",
        help="Directory containing official Chrome old.xml and new.xml XCCDF files.",
    ),
    impact_filter: Optional[str] = typer.Option(None, "--impact", help="Only include one impact category, such as high_priority_review."),
    owner_filter: Optional[str] = typer.Option(None, "--owner", help='Only include changes for one suggested owner, such as "Endpoint/Windows Admin".'),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate a Chrome for Windows STIG comparison packet."""

    root = Path(__file__).resolve().parents[1]
    official_old = input_dir / "old.xml"
    official_new = input_dir / "new.xml"
    sample_old = root / "examples" / "chrome_windows_sample" / "old.xml"
    sample_new = root / "examples" / "chrome_windows_sample" / "new.xml"

    using_official = official_old.exists() and official_new.exists()
    if using_official:
        old_xml = official_old
        new_xml = official_new
        source_label = "Official/user-supplied Chrome STIG files"
    else:
        _print_chrome_missing_message(input_dir, sample_old, sample_new)
        old_xml = sample_old
        new_xml = sample_new
        source_label = "Bundled sanitized Chrome sample"

    config = _load_config(config_path)
    old_doc = _load(old_xml, config)
    new_doc = _load(new_xml, config)
    if not using_official:
        _prefer_repo_relative_source(old_doc, root)
        _prefer_repo_relative_source(new_doc, root)
    all_changes = compare_documents(old_doc, new_doc)
    changes = _filter_changes(all_changes, impact_filter, owner_filter, config)
    outputs = _write_comparison_packet(old_doc, new_doc, changes, out, config)

    counts = change_summary_counts(changes)
    table = Table(title="Chrome STIG Demo", header_style="bold blue", border_style="dim", show_lines=False)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Source", source_label)
    table.add_row("STIG name", new_doc.title or old_doc.title or "Google Chrome for Windows")
    table.add_row("Old release", old_doc.release or old_doc.version or "Unknown")
    table.add_row("New release", new_doc.release or new_doc.version or "Unknown")
    table.add_row("Old control count", str(len(old_doc.controls)))
    table.add_row("New control count", str(len(new_doc.controls)))
    table.add_row("Added", str(counts["added"]))
    table.add_row("Removed", str(counts["removed"]))
    table.add_row("Modified", str(counts["modified"]))
    table.add_row("Severity increased", str(sum(1 for change in changes if change.change_type == "severity_increased")))
    table.add_row("High-priority review", str(counts["high_priority_review"]))
    table.add_row("Implementation change likely", str(counts["implementation_change_likely"]))
    table.add_row("Evidence update likely", str(counts["evidence_update_likely"]))
    table.add_row("Output directory", str(out))
    console.print(table)
    _print_outputs_table("Chrome Reports Generated", outputs)
    console.print(f"[bold]Start here:[/bold] {outputs['Start here']}")


@app.command("config-example")
def config_example(
    out: Path = typer.Option(Path("stigpilot.toml"), "--out", help="Where to write the example TOML config."),
) -> None:
    """Write an example local owner/tag mapping config."""

    _safe_write(lambda: out.write_text(CONFIG_EXAMPLE, encoding="utf-8"), out, "config example")


def _packet_expected_files(packet_dir: Path) -> list[str]:
    start_here = packet_dir / "START_HERE.md"
    start_here_text = start_here.read_text(encoding="utf-8", errors="replace") if start_here.exists() else ""
    expected_files = list(PACKET_COMMON_FILES)
    if any(filename in start_here_text for filename in PACKET_PYTHON_EXTRA_FILES):
        expected_files.extend(PACKET_PYTHON_EXTRA_FILES)
    return expected_files


def _inspect_packet(packet_dir: Path) -> tuple[list[tuple[str, bool, str]], dict[str, object]]:
    if not packet_dir.exists():
        return [("<packet directory>", False, "missing")], {}
    if not packet_dir.is_dir():
        return [("<packet directory>", False, "not a directory")], {}

    rows: list[tuple[str, bool, str]] = []
    change_summary: dict[str, object] = {}
    for filename in _packet_expected_files(packet_dir):
        path = packet_dir / filename
        if not path.exists():
            rows.append((filename, False, "missing"))
        elif path.stat().st_size == 0:
            rows.append((filename, False, "empty"))
        elif filename == "changes.json":
            try:
                payload = json.loads(path.read_text(encoding="utf-8-sig"))
                summary = payload.get("summary", {})
                if isinstance(summary, dict):
                    change_summary = summary
                rows.append((filename, True, f"{path.stat().st_size} bytes"))
            except (json.JSONDecodeError, OSError) as exc:
                rows.append((filename, False, f"invalid JSON: {exc}"))
        else:
            rows.append((filename, True, f"{path.stat().st_size} bytes"))
    return rows, change_summary


def _print_packet_inspection(packet_dir: Path, rows: list[tuple[str, bool, str]], change_summary: dict[str, object]) -> None:
    if not packet_dir.exists():
        console.print(f"[red]Packet directory not found:[/red] {packet_dir}")
    elif not packet_dir.is_dir():
        console.print(f"[red]Packet path is not a directory:[/red] {packet_dir}")

    table = Table(title="STIGPilot Packet Inspection", header_style="bold blue", border_style="dim", show_lines=False)
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Details")
    for filename, ok, detail in rows:
        table.add_row(filename, "[green]PASS[/green]" if ok else "[red]FAIL[/red]", detail)
    console.print(table)

    if change_summary:
        console.print(
            "[bold]Change summary:[/bold] "
            f"{change_summary.get('total', 0)} total, "
            f"{change_summary.get('high_priority_review', 0)} high-priority, "
            f"{change_summary.get('implementation_change_likely', 0)} implementation-likely, "
            f"{change_summary.get('evidence_update_likely', 0)} evidence-update-likely."
        )


@app.command("inspect-output")
def inspect_output(
    packet_dir: Path = typer.Argument(..., help="Generated STIGPilot packet directory to inspect."),
) -> None:
    """Check whether a generated packet is complete enough to hand off."""

    rows, change_summary = _inspect_packet(packet_dir)
    _print_packet_inspection(packet_dir, rows, change_summary)

    if all(ok for _, ok, _ in rows):
        console.print(f"[green]Packet is handoff-ready:[/green] {packet_dir}")
        console.print(f"[bold]Start here:[/bold] {packet_dir / 'START_HERE.md'}")
    else:
        console.print(f"[red]Packet is incomplete:[/red] {packet_dir}")
        raise typer.Exit(1)


@app.command("archive-output")
def archive_output(
    packet_dir: Path = typer.Argument(..., help="Generated STIGPilot packet directory to archive."),
    out: Optional[Path] = typer.Option(None, "--out", help="ZIP path to write. Defaults to PACKET_DIR.zip."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing ZIP file."),
) -> None:
    """Validate a packet and write a ZIP archive for local handoff."""

    rows, change_summary = _inspect_packet(packet_dir)
    _print_packet_inspection(packet_dir, rows, change_summary)
    if not all(ok for _, ok, _ in rows):
        console.print(f"[red]Archive skipped because packet is incomplete:[/red] {packet_dir}")
        raise typer.Exit(1)

    zip_path = out or packet_dir.with_suffix(".zip")
    if zip_path.exists() and not force:
        console.print(f"[red]Archive already exists:[/red] {zip_path}")
        console.print("Use --force to overwrite it.")
        raise typer.Exit(1)
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(packet_dir.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(packet_dir.parent))

    console.print(f"[green]Wrote packet archive:[/green] {zip_path}")
    console.print(f"[bold]Archived folder:[/bold] {packet_dir}")


@app.command()
def doctor() -> None:
    """Run a local reality check for STIGPilot."""

    root = Path(__file__).resolve().parents[1]
    checks: list[tuple[str, bool, str]] = []
    checks.append(("Python version", sys.version_info >= (3, 11), sys.version.split()[0]))
    checks.append(("stigpilot import", importlib.util.find_spec("stigpilot") is not None, "package importable"))
    checks.append(("typer installed", importlib.util.find_spec("typer") is not None, "required CLI dependency"))
    checks.append(("rich installed", importlib.util.find_spec("rich") is not None, "required terminal dependency"))
    checks.append(("examples directory", (root / "examples").exists(), str(root / "examples")))
    old_xml = root / "examples" / "sample_input" / "old.xml"
    new_xml = root / "examples" / "sample_input" / "new.xml"
    checks.append(("sample old XML", old_xml.exists(), str(old_xml)))
    checks.append(("sample new XML", new_xml.exists(), str(new_xml)))
    output_dir = root / "output"
    try:
        output_dir.mkdir(exist_ok=True)
        probe = output_dir / ".stigpilot-doctor"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        writable = True
        detail = str(output_dir)
    except OSError as exc:
        writable = False
        detail = str(exc)
    checks.append(("output writable", writable, detail))
    try:
        old_doc = parse_stig(old_xml)
        new_doc = parse_stig(new_xml)
        changes = compare_documents(old_doc, new_doc)
        checks.append(("sample parse", len(old_doc.controls) > 0 and len(new_doc.controls) > 0, f"{len(old_doc.controls)} old / {len(new_doc.controls)} new controls"))
        checks.append(("sample diff", len(changes) > 0, f"{len(changes)} changes"))
    except StigParseError as exc:
        checks.append(("sample parse/diff", False, str(exc)))

    table = Table(title="STIGPilot Doctor", header_style="bold blue", border_style="dim", show_lines=False)
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Details")
    for name, ok, detail in checks:
        table.add_row(name, "[green]PASS[/green]" if ok else "[red]FAIL[/red]", detail)
    console.print(table)
    console.print("Tests: run [bold]python -m pytest[/bold]")
    if not all(ok for _, ok, _ in checks):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
