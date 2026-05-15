"""Command line interface for STIGPilot."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .config import StigPilotConfig, load_config
from .diff import compare_documents
from .exporters import (
    github_issue_markdown,
    write_backlog_csv,
    write_controls_csv,
    write_controls_json,
    write_jira_csv,
    write_servicenow_csv,
    write_ticket_csv,
)
from .parser import StigParseError, parse_stig
from .reports import change_brief, evidence_checklist, filter_by_severity, manager_summary_report, single_stig_brief, write_text_report
from .taxonomy import suggested_owner

app = typer.Typer(help="STIGPilot: STIG change intelligence and remediation workflow assistance.")
console = Console()


def _load_config(config_path: Path | None) -> StigPilotConfig | None:
    try:
        return load_config(config_path)
    except ValueError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(1) from exc


def _load(path: Path, config: StigPilotConfig | None = None):
    try:
        document = parse_stig(path, config)
    except StigParseError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc
    if not document.controls:
        console.print(f"[yellow]Warning:[/yellow] No Rule controls found in {path}")
    return document


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
        write_controls_csv(document, csv_out)
        console.print(f"[green]Wrote CSV:[/green] {csv_out}")
    if json_out:
        write_controls_json(document, json_out)
        console.print(f"[green]Wrote JSON:[/green] {json_out}")
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
    write_text_report(out, single_stig_brief(document, severity, config))
    console.print(f"[green]Wrote brief:[/green] {out}")


@app.command()
def diff(
    old_xml: Path = typer.Argument(..., exists=True, readable=True),
    new_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Markdown change brief output path."),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Remediation backlog CSV output path."),
    jira_csv: Optional[Path] = typer.Option(None, "--jira-csv", help="Jira-friendly CSV output path."),
    servicenow_csv: Optional[Path] = typer.Option(None, "--servicenow-csv", help="ServiceNow-friendly CSV output path."),
    github_md: Optional[Path] = typer.Option(None, "--github-md", help="GitHub issue draft Markdown output path."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Compare two STIG versions and generate a change brief."""

    config = _load_config(config_path)
    old_doc = _load(old_xml, config)
    new_doc = _load(new_xml, config)
    changes = compare_documents(old_doc, new_doc)
    write_text_report(out, change_brief(old_doc, new_doc, changes, config))
    console.print(f"[green]Wrote change brief:[/green] {out}")
    if csv_out:
        write_backlog_csv(changes, csv_out, config)
        console.print(f"[green]Wrote backlog CSV:[/green] {csv_out}")
    if jira_csv:
        write_jira_csv(changes, jira_csv, config)
        console.print(f"[green]Wrote Jira CSV:[/green] {jira_csv}")
    if servicenow_csv:
        write_servicenow_csv(changes, servicenow_csv, config)
        console.print(f"[green]Wrote ServiceNow CSV:[/green] {servicenow_csv}")
    if github_md:
        write_text_report(github_md, github_issue_markdown(changes, config))
        console.print(f"[green]Wrote GitHub issue drafts:[/green] {github_md}")
    console.print(f"Detected {len(changes)} changes.")


@app.command()
def manager(
    old_xml: Path = typer.Argument(..., exists=True, readable=True),
    new_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Manager-facing Markdown summary output path."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Generate a concise manager-facing summary for a STIG version comparison."""

    config = _load_config(config_path)
    old_doc = _load(old_xml, config)
    new_doc = _load(new_xml, config)
    changes = compare_documents(old_doc, new_doc)
    write_text_report(out, manager_summary_report(old_doc, new_doc, changes, config))
    console.print(f"[green]Wrote manager summary:[/green] {out}")
    console.print(f"Detected {len(changes)} changes.")


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
    write_ticket_csv(controls, out, config)
    console.print(f"[green]Wrote ticket CSV:[/green] {out}")


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
    write_text_report(out, evidence_checklist(document, severity, config))
    console.print(f"[green]Wrote evidence checklist:[/green] {out}")


@app.command()
def summary(
    input_xml: Path = typer.Argument(..., exists=True, readable=True),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Optional local TOML owner/tag mapping config."),
) -> None:
    """Show a terminal summary for one STIG file."""

    config = _load_config(config_path)
    document = _load(input_xml, config)
    table = Table(title=document.title or "STIG Summary")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    counts: dict[str, int] = {}
    for control in document.controls:
        key = control.severity or "unspecified"
        counts[key] = counts.get(key, 0) + 1
    for severity, count in sorted(counts.items()):
        table.add_row(severity, str(count))
    console.print(table)
    console.print(f"Source: {input_xml}")
    console.print(f"Version: {document.version or 'Unknown'} | Release: {document.release or 'Unknown'}")
    console.print(f"Controls: {len(document.controls)}")

    owner_table = Table(title="Suggested Owner Summary")
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
    changes = compare_documents(old_doc, new_doc)

    write_controls_csv(new_doc, out / "controls.csv")
    write_controls_json(new_doc, out / "controls.json")
    write_text_report(out / "brief.md", single_stig_brief(new_doc, config=config))
    write_text_report(out / "change-brief.md", change_brief(old_doc, new_doc, changes, config))
    write_text_report(out / "manager-summary.md", manager_summary_report(old_doc, new_doc, changes, config))
    write_backlog_csv(changes, out / "remediation-backlog.csv", config)
    write_text_report(out / "evidence-checklist.md", evidence_checklist(new_doc, config=config))
    write_jira_csv(changes, out / "jira-import.csv", config)
    write_servicenow_csv(changes, out / "servicenow-import.csv", config)
    write_text_report(out / "github-issues.md", github_issue_markdown(changes, config))

    console.print(f"[green]Demo reports generated:[/green] {out}")
    console.print("Open change-brief.md, remediation-backlog.csv, and evidence-checklist.md first.")


if __name__ == "__main__":
    app()
