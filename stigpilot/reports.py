"""Markdown report generation."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .config import StigPilotConfig
from .impact import evidence_requests
from .models import ControlChange, StigControl, StigDocument
from .taxonomy import suggested_owner
from .utils import ensure_parent, summarize


def write_text_report(path: str | Path, content: str) -> None:
    ensure_parent(path)
    Path(path).write_text(content, encoding="utf-8")


def single_stig_brief(document: StigDocument, severity: str | None = None, config: StigPilotConfig | None = None) -> str:
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
    lines.extend(["", "## Controls", "", "| Severity | Vuln ID | Rule ID | Title | Owner | Tags |", "| --- | --- | --- | --- | --- | --- |"])
    for control in controls:
        lines.append(
            f"| {control.severity or ''} | {control.vuln_id or ''} | {control.rule_id or ''} | "
            f"{_md(control.title)} | {suggested_owner(control, config)} | {_md(', '.join(control.tags))} |"
        )
    return "\n".join(lines) + "\n"


def change_brief(
    old_doc: StigDocument,
    new_doc: StigDocument,
    changes: list[ControlChange],
    config: StigPilotConfig | None = None,
) -> str:
    counts = Counter(change.change_type for change in changes)
    impacts = Counter(change.impact for change in changes)
    severity_changed_count = sum(1 for change in changes if "severity" in change.changed_fields)
    check_changed_count = sum(1 for change in changes if "check_text" in change.changed_fields)
    fix_changed_count = sum(1 for change in changes if "fix_text" in change.changed_fields)
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
        f"- Check text changed: {check_changed_count}",
        f"- Fix text changed: {fix_changed_count}",
        f"- High-priority review: {impacts.get('high_priority_review', 0)}",
        f"- Implementation change likely: {impacts.get('implementation_change_likely', 0)}",
        f"- Evidence update likely: {impacts.get('evidence_update_likely', 0)}",
        f"- Review recommended: {impacts.get('review_recommended', 0)}",
        f"- No action likely: {impacts.get('no_action_likely', 0)}",
        "",
        "## Manager Summary",
        "",
        manager_summary(changes, config),
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
            "| Change | Impact | Severity | Vuln ID | Rule ID | Changed Fields | Owner | Tags | Reason |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for change in changes:
        control = change.current_control or StigControl()
        lines.append(
            f"| {change.change_type} | {change.impact} | {control.severity or ''} | "
            f"{control.vuln_id or change.vuln_id} | {control.rule_id or change.rule_id} | "
            f"{', '.join(change.changed_fields) or '-'} | {suggested_owner(control, config)} | "
            f"{_md(', '.join(control.tags))} | {_md(change.reason)} |"
        )
    return "\n".join(lines) + "\n"


def manager_summary_report(
    old_doc: StigDocument,
    new_doc: StigDocument,
    changes: list[ControlChange],
    config: StigPilotConfig | None = None,
) -> str:
    """Generate a concise manager-facing Markdown report."""

    impacts = Counter(change.impact for change in changes)
    owners = Counter(suggested_owner(change.current_control, config) for change in changes)
    priority_changes = [
        change
        for change in changes
        if change.impact in {"high_priority_review", "implementation_change_likely", "evidence_update_likely"}
    ][:10]
    lines = [
        "# STIGPilot Manager Summary",
        "",
        f"Old source: `{Path(old_doc.source_file).name}`",
        f"New source: `{Path(new_doc.source_file).name}`",
        f"Old controls: {len(old_doc.controls)}",
        f"New controls: {len(new_doc.controls)}",
        "",
        "## Executive Readout",
        "",
        manager_summary(changes, config),
        "",
        "## Workload Snapshot",
        "",
        f"- Total changes: {len(changes)}",
        f"- High-priority review: {impacts.get('high_priority_review', 0)}",
        f"- Implementation change likely: {impacts.get('implementation_change_likely', 0)}",
        f"- Evidence update likely: {impacts.get('evidence_update_likely', 0)}",
        f"- Review recommended: {impacts.get('review_recommended', 0)}",
        f"- No action likely: {impacts.get('no_action_likely', 0)}",
        "",
        "## Owner Impact",
        "",
    ]
    if owners:
        for owner, count in owners.most_common():
            lines.append(f"- {owner}: {count}")
    else:
        lines.append("- No owner impact detected.")

    lines.extend(["", "## Top Actions", ""])
    if not priority_changes:
        lines.append("- No high-priority implementation or evidence actions were detected.")
    for change in priority_changes:
        control = change.current_control or StigControl()
        lines.append(
            f"- {control.vuln_id or control.rule_id or 'Control'}: {control.title or 'Untitled'} "
            f"({change.impact}; {suggested_owner(control, config)})"
        )

    lines.extend(
        [
            "",
            "## Recommended Next Steps",
            "",
            "- Assign high-priority and implementation-likely changes to the suggested owner groups.",
            "- Use the remediation backlog CSV for ticket import or queue grooming.",
            "- Use the evidence checklist to refresh validation requests where check guidance changed.",
        ]
    )
    return "\n".join(lines) + "\n"


def evidence_checklist(document: StigDocument, severity: str | None = None, config: StigPilotConfig | None = None) -> str:
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
                f"- Suggested owner: {suggested_owner(control, config)}",
                f"- Tags: {', '.join(control.tags)}",
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


def manager_summary(changes: list[ControlChange], config: StigPilotConfig | None = None) -> str:
    if not changes:
        return "No STIG control changes were detected between the compared files."
    impacts = Counter(change.impact for change in changes)
    owners = Counter(suggested_owner(change.current_control, config) for change in changes)
    top_count = owners.most_common(1)[0][1]
    top_owners = sorted(owner for owner, count in owners.items() if count == top_count)
    owner_phrase = ", ".join(top_owners) if len(top_owners) <= 3 else "multiple owner groups"
    action_count = impacts.get("high_priority_review", 0) + impacts.get("implementation_change_likely", 0) + impacts.get("evidence_update_likely", 0)
    return (
        f"{len(changes)} control change(s) were detected. "
        f"{action_count} likely require priority review, implementation work, or evidence updates. "
        f"The most affected owner group is {owner_phrase}. "
        "Use the backlog CSV to assign review work and the evidence checklist to prepare validation requests."
    )


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
