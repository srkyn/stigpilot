"""Markdown report generation."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .impact import evidence_requests, suggested_owner
from .models import ControlChange, StigControl, StigDocument
from .utils import ensure_parent, summarize


def write_text_report(path: str | Path, content: str) -> None:
    ensure_parent(path)
    Path(path).write_text(content, encoding="utf-8")


def single_stig_brief(document: StigDocument, severity: str | None = None) -> str:
    controls = filter_by_severity(document.controls, severity)
    counts = Counter((control.severity or "unspecified").lower() for control in controls)
    lines = [
        "# STIGPilot Brief",
        "",
        f"Source: `{Path(document.source_file).name}`",
        f"Title: {document.title or 'Unknown'}",
        f"Version: {document.version or 'Unknown'}",
        f"Release: {document.release or 'Unknown'}",
        f"Controls included: {len(controls)}",
        "",
        "## Severity Summary",
        "",
    ]
    for name in ("high", "medium", "low", "unspecified"):
        lines.append(f"- {name}: {counts.get(name, 0)}")
    lines.extend(["", "## Controls", "", "| Severity | Vuln ID | Rule ID | Title | Owner |", "| --- | --- | --- | --- | --- |"])
    for control in controls:
        lines.append(
            f"| {control.severity or ''} | {control.vuln_id or ''} | {control.rule_id or ''} | "
            f"{_md(control.title)} | {suggested_owner(control)} |"
        )
    return "\n".join(lines) + "\n"


def change_brief(old_doc: StigDocument, new_doc: StigDocument, changes: list[ControlChange]) -> str:
    counts = Counter(change.change_type for change in changes)
    impacts = Counter(change.impact for change in changes)
    severity_changed_count = sum(1 for change in changes if "severity" in change.changed_fields)
    top = [
        change
        for change in changes
        if change.impact in {"high_priority_review", "implementation_change_likely", "evidence_update_likely"}
    ][:10]
    lines = [
        "# STIGPilot Change Brief",
        "",
        f"Old source: `{Path(old_doc.source_file).name}`",
        f"New source: `{Path(new_doc.source_file).name}`",
        f"Total controls old: {len(old_doc.controls)}",
        f"Total controls new: {len(new_doc.controls)}",
        "",
        "## Change Summary",
        "",
        f"- Added: {counts.get('added', 0)}",
        f"- Removed: {counts.get('removed', 0)}",
        f"- Modified: {counts.get('modified', 0)}",
        f"- Severity changed: {severity_changed_count}",
        f"- High-priority review: {impacts.get('high_priority_review', 0)}",
        f"- Implementation change likely: {impacts.get('implementation_change_likely', 0)}",
        f"- Evidence update likely: {impacts.get('evidence_update_likely', 0)}",
        "",
        "## Top Priority Actions",
        "",
    ]
    if not top:
        lines.append("- No high-priority implementation or evidence changes detected.")
    for change in top:
        control = change.current_control or StigControl()
        lines.append(
            f"- **{change.impact}**: {control.vuln_id or control.rule_id} - "
            f"{control.title or 'Untitled'} ({change.reason})"
        )
    lines.extend(
        [
            "",
            "## Detailed Changes",
            "",
            "| Change | Impact | Severity | Vuln ID | Rule ID | Changed Fields | Owner | Reason |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for change in changes:
        control = change.current_control or StigControl()
        lines.append(
            f"| {change.change_type} | {change.impact} | {control.severity or ''} | "
            f"{control.vuln_id or change.vuln_id} | {control.rule_id or change.rule_id} | "
            f"{', '.join(change.changed_fields) or '-'} | {suggested_owner(control)} | {_md(change.reason)} |"
        )
    return "\n".join(lines) + "\n"


def evidence_checklist(document: StigDocument, severity: str | None = None) -> str:
    controls = filter_by_severity(document.controls, severity)
    lines = [
        "# STIGPilot Evidence Checklist",
        "",
        f"Source: `{Path(document.source_file).name}`",
        f"Controls included: {len(controls)}",
        "",
    ]
    for control in controls:
        lines.extend(
            [
                f"## {control.vuln_id or control.rule_id or 'Control'} - {control.title or 'Untitled'}",
                "",
                f"- Severity: {control.severity or 'unspecified'}",
                f"- Suggested owner: {suggested_owner(control)}",
                f"- Check summary: {summarize(control.check_text)}",
                "- Evidence requested:",
            ]
        )
        for request in evidence_requests(control):
            lines.append(f"  - {request}")
        lines.append("")
    return "\n".join(lines)


def filter_by_severity(controls: list[StigControl], severity: str | None) -> list[StigControl]:
    if not severity:
        return list(controls)
    wanted = severity.lower()
    return [control for control in controls if control.severity.lower() == wanted]


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
