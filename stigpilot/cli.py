"""Command line interface for STIGPilot."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .diff import compare_documents
from .exporters import write_backlog_csv, write_controls_csv, write_controls_json, write_ticket_csv
from .parser import StigParseError, parse_stig
from .reports import change_brief, evidence_checklist, filter_by_severity, single_stig_brief, write_text_report

app = typer.Typer(help="STIGPilot: STIG change intelligence and remediation workflow assistance.")
console = Console()


def _load(path: Path):
    try:
        return parse_stig(path)
    except StigParseError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc


@app.command()
def parse(
    input_xml: Path = typer.Argument(..., exists=True, readable=True, help="STIG XCCDF/XML input file."),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Write parsed controls to CSV."),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write parsed controls to JSON."),
) -> None:
    """Parse a STIG and export normalized controls."""

    document = _load(input_xml)
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
) -> None:
    """Generate a readable Markdown brief from one STIG file."""

    document = _load(input_xml)
    write_text_report(out, single_stig_brief(document, severity))
    console.print(f"[green]Wrote brief:[/green] {out}")


@app.command()
def diff(
    old_xml: Path = typer.Argument(..., exists=True, readable=True),
    new_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Markdown change brief output path."),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Remediation backlog CSV output path."),
) -> None:
    """Compare two STIG versions and generate a change brief."""

    old_doc = _load(old_xml)
    new_doc = _load(new_xml)
    changes = compare_documents(old_doc, new_doc)
    write_text_report(out, change_brief(old_doc, new_doc, changes))
    console.print(f"[green]Wrote change brief:[/green] {out}")
    if csv_out:
        write_backlog_csv(changes, csv_out)
        console.print(f"[green]Wrote backlog CSV:[/green] {csv_out}")
    console.print(f"Detected {len(changes)} changes.")


@app.command()
def tickets(
    input_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Ticket-friendly CSV output path."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Optional severity filter, such as high."),
) -> None:
    """Generate a ticket-ready export for controls."""

    document = _load(input_xml)
    controls = filter_by_severity(document.controls, severity)
    write_ticket_csv(controls, out)
    console.print(f"[green]Wrote ticket CSV:[/green] {out}")


@app.command()
def evidence(
    input_xml: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Markdown checklist output path."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Optional severity filter."),
) -> None:
    """Generate a Markdown evidence checklist."""

    document = _load(input_xml)
    write_text_report(out, evidence_checklist(document, severity))
    console.print(f"[green]Wrote evidence checklist:[/green] {out}")


@app.command()
def summary(input_xml: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Show a terminal summary for one STIG file."""

    document = _load(input_xml)
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


if __name__ == "__main__":
    app()
