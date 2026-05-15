"""CSV and JSON export helpers."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .impact import evidence_requests
from .models import ControlChange, StigControl, StigDocument
from .taxonomy import suggested_owner
from .utils import ensure_parent, summarize


CONTROL_FIELDS = [
    "vuln_id",
    "rule_id",
    "group_id",
    "stig_id",
    "title",
    "severity",
    "check_text",
    "fix_text",
    "cci_refs",
    "references",
    "tags",
    "raw_id",
]


def write_controls_csv(document: StigDocument, path: str | Path) -> None:
    ensure_parent(path)
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CONTROL_FIELDS)
        writer.writeheader()
        for control in document.controls:
            row = asdict(control)
            row["cci_refs"] = "; ".join(control.cci_refs)
            row["references"] = "; ".join(control.references)
            row["tags"] = "; ".join(control.tags)
            writer.writerow(row)


def write_controls_json(document: StigDocument, path: str | Path) -> None:
    ensure_parent(path)
    payload = asdict(document)
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


BACKLOG_FIELDS = [
    "title",
    "vuln_id",
    "rule_id",
    "severity",
    "change_type",
    "impact",
    "reason",
    "suggested_owner",
    "tags",
    "check_summary",
    "fix_summary",
    "evidence_needed",
    "status",
    "notes",
]


def write_backlog_csv(changes: Iterable[ControlChange], path: str | Path) -> None:
    ensure_parent(path)
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=BACKLOG_FIELDS)
        writer.writeheader()
        for change in changes:
            writer.writerow(backlog_row(change))


def backlog_row(change: ControlChange) -> dict[str, str]:
    control = change.current_control or StigControl()
    return {
        "title": control.title,
        "vuln_id": control.vuln_id or change.vuln_id,
        "rule_id": control.rule_id or change.rule_id,
        "severity": control.severity,
        "change_type": change.change_type,
        "impact": change.impact,
        "reason": change.reason,
        "suggested_owner": suggested_owner(control),
        "tags": "; ".join(control.tags),
        "check_summary": summarize(control.check_text),
        "fix_summary": summarize(control.fix_text),
        "evidence_needed": "; ".join(evidence_requests(control)),
        "status": "Not Started",
        "notes": "",
    }


def write_ticket_csv(controls: Iterable[StigControl], path: str | Path) -> None:
    ensure_parent(path)
    fields = [
        "title",
        "vuln_id",
        "rule_id",
        "severity",
        "suggested_owner",
        "tags",
        "ticket_summary",
        "description",
        "evidence_needed",
        "status",
        "notes",
    ]
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for control in controls:
            writer.writerow(
                {
                    "title": control.title,
                    "vuln_id": control.vuln_id,
                    "rule_id": control.rule_id,
                    "severity": control.severity,
                    "suggested_owner": suggested_owner(control),
                    "tags": "; ".join(control.tags),
                    "ticket_summary": f"Review STIG control {control.vuln_id or control.rule_id}: {control.title}",
                    "description": summarize(f"Check: {control.check_text} Fix: {control.fix_text}", 500),
                    "evidence_needed": "; ".join(evidence_requests(control)),
                    "status": "Not Started",
                    "notes": "",
                }
            )


def write_jira_csv(changes: Iterable[ControlChange], path: str | Path) -> None:
    """Write a Jira-friendly CSV import with Summary and Description fields."""

    ensure_parent(path)
    fields = ["Summary", "Issue Type", "Priority", "Labels", "Assignee", "Description"]
    with Path(path).open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for change in changes:
            control = change.current_control or StigControl()
            writer.writerow(
                {
                    "Summary": f"{change.change_type}: {control.vuln_id or control.rule_id} - {control.title}",
                    "Issue Type": "Task",
                    "Priority": _priority(change),
                    "Labels": ",".join(["stigpilot", change.impact] + [tag.lower().replace("/", "-").replace(" ", "-") for tag in control.tags]),
                    "Assignee": suggested_owner(control),
                    "Description": _ticket_description(change),
                }
            )


def write_servicenow_csv(changes: Iterable[ControlChange], path: str | Path) -> None:
    """Write a ServiceNow-friendly local CSV."""

    ensure_parent(path)
    fields = ["short_description", "description", "assignment_group", "priority", "u_stig_vuln_id", "u_stig_rule_id", "u_impact", "u_tags"]
    with Path(path).open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for change in changes:
            control = change.current_control or StigControl()
            writer.writerow(
                {
                    "short_description": f"Review STIG change {control.vuln_id or control.rule_id}: {control.title}",
                    "description": _ticket_description(change),
                    "assignment_group": suggested_owner(control),
                    "priority": _priority(change),
                    "u_stig_vuln_id": control.vuln_id or change.vuln_id,
                    "u_stig_rule_id": control.rule_id or change.rule_id,
                    "u_impact": change.impact,
                    "u_tags": "; ".join(control.tags),
                }
            )


def github_issue_markdown(changes: Iterable[ControlChange]) -> str:
    """Generate copy/paste-ready GitHub issue Markdown sections."""

    lines = ["# STIGPilot GitHub Issue Drafts", ""]
    for idx, change in enumerate(changes, start=1):
        control = change.current_control or StigControl()
        lines.extend(
            [
                f"## Issue {idx}: {change.change_type}: {control.vuln_id or control.rule_id} - {control.title}",
                "",
                f"Labels: `stigpilot`, `{change.impact}`, " + ", ".join(f"`{tag}`" for tag in control.tags),
                "",
                "### Context",
                "",
                f"- Severity: {control.severity or 'unspecified'}",
                f"- Suggested owner: {suggested_owner(control)}",
                f"- Impact: {change.impact}",
                f"- Reason: {change.reason}",
                f"- Changed fields: {', '.join(change.changed_fields) or change.change_type}",
                "",
                "### Evidence Needed",
                "",
            ]
        )
        for item in evidence_requests(control):
            lines.append(f"- [ ] {item}")
        lines.extend(["", "### Notes", "", "- ", ""])
    return "\n".join(lines)


def _ticket_description(change: ControlChange) -> str:
    control = change.current_control or StigControl()
    return "\n".join(
        [
            f"Change type: {change.change_type}",
            f"Impact: {change.impact}",
            f"Reason: {change.reason}",
            f"Changed fields: {', '.join(change.changed_fields) or change.change_type}",
            f"Vuln ID: {control.vuln_id or change.vuln_id}",
            f"Rule ID: {control.rule_id or change.rule_id}",
            f"Tags: {', '.join(control.tags)}",
            f"Check summary: {summarize(control.check_text, 400)}",
            f"Fix summary: {summarize(control.fix_text, 400)}",
            "Evidence needed: " + "; ".join(evidence_requests(control)),
        ]
    )


def _priority(change: ControlChange) -> str:
    if change.impact == "high_priority_review":
        return "High"
    if change.impact in {"implementation_change_likely", "evidence_update_likely"}:
        return "Medium"
    return "Low"
