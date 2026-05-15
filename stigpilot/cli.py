"""Command line interface for STIGPilot."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .config import CONFIG_EXAMPLE, StigPilotConfig, load_config
from .diff import compare_documents, duplicate_keys
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
from .reports import change_brief, change_summary_counts, evidence_checklist, filter_by_severity, manager_summary_report, single_stig_brief, write_text_report
from .taxonomy import suggested_owner

app = typer.Typer(
    help="Turn DISA STIG XCCDF release changes into briefs, backlogs, evidence checklists, and ticket-ready exports.",
    no_args_is_help=True,
)
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
    table = Table(title="STIGPilot Diff Summary")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    for label, key in (
        ("Total changes", "total"),
        ("Added", "added"),
        ("Removed", "removed"),
        ("Modified", "modified"),
        ("Severity changed", "severity_changed"),
        ("High-priority review", "high_priority_review"),
        ("Implementation change likely", "implementation_change_likely"),
        ("Evidence update likely", "evidence_update_likely"),
    ):
        table.add_row(label, str(counts[key]))
    console.print(table)
    if outputs:
        console.print("[bold]Written files:[/bold]")
        for output in outputs:
            console.print(f"- {output}")


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
    changes = compare_documents(old_doc, new_doc)
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
    _print_change_summary(changes, outputs)


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
    _warn_same_inputs(old_xml, new_xml, old_doc, new_doc)
    changes = compare_documents(old_doc, new_doc)
    _safe_write(lambda: write_text_report(out, manager_summary_report(old_doc, new_doc, changes, config)), out, "manager summary")
    _print_change_summary(changes, [out])


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

    outputs = {
        "Controls CSV": out / "controls.csv",
        "Controls JSON": out / "controls.json",
        "Brief": out / "brief.md",
        "Change brief": out / "change-brief.md",
        "Manager summary": out / "manager-summary.md",
        "Remediation backlog": out / "remediation-backlog.csv",
        "Evidence checklist": out / "evidence-checklist.md",
        "Jira import": out / "jira-import.csv",
        "ServiceNow import": out / "servicenow-import.csv",
        "GitHub issues": out / "github-issues.md",
    }
    write_controls_csv(new_doc, outputs["Controls CSV"])
    write_controls_json(new_doc, outputs["Controls JSON"])
    write_text_report(outputs["Brief"], single_stig_brief(new_doc, config=config))
    write_text_report(outputs["Change brief"], change_brief(old_doc, new_doc, changes, config))
    write_text_report(outputs["Manager summary"], manager_summary_report(old_doc, new_doc, changes, config))
    write_backlog_csv(changes, outputs["Remediation backlog"], config)
    write_text_report(outputs["Evidence checklist"], evidence_checklist(new_doc, config=config))
    write_jira_csv(changes, outputs["Jira import"], config)
    write_servicenow_csv(changes, outputs["ServiceNow import"], config)
    write_text_report(outputs["GitHub issues"], github_issue_markdown(changes, config))

    table = Table(title="Demo Reports Generated")
    table.add_column("Report")
    table.add_column("Path")
    for name, path in outputs.items():
        table.add_row(name, str(path))
    console.print(table)
    _print_change_summary(changes, [])
    console.print("[bold]Start here:[/bold]")
    console.print(f"- Open {outputs['Change brief']}")
    console.print(f"- Open {outputs['Manager summary']}")
    console.print(f"- Open {outputs['Remediation backlog']}")


@app.command("config-example")
def config_example(
    out: Path = typer.Option(Path("stigpilot.toml"), "--out", help="Where to write the example TOML config."),
) -> None:
    """Write an example local owner/tag mapping config."""

    _safe_write(lambda: out.write_text(CONFIG_EXAMPLE, encoding="utf-8"), out, "config example")


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

    table = Table(title="STIGPilot Doctor")
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
