"""CSV and JSON export helpers."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .config import StigPilotConfig
from .impact import evidence_requests
from .models import ControlChange, StigControl, StigDocument
from .taxonomy import suggested_owner
from .utils import ensure_parent, summarize


CONTROL_FIELDS = [
    "Vuln ID",
    "Rule ID",
    "Group ID",
    "STIG ID",
    "Title",
    "Severity",
    "Check Text",
    "Fix Text",
    "CCI References",
    "References",
    "Tags",
    "Raw ID",
]


def write_controls_csv(document: StigDocument, path: str | Path) -> None:
    ensure_parent(path)
    with Path(path).open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=CONTROL_FIELDS)
        writer.writeheader()
        for control in document.controls:
            writer.writerow(
                {
                    "Vuln ID": control.vuln_id,
                    "Rule ID": control.rule_id,
                    "Group ID": control.group_id,
                    "STIG ID": control.stig_id,
                    "Title": control.title,
                    "Severity": control.severity,
                    "Check Text": control.check_text,
                    "Fix Text": control.fix_text,
                    "CCI References": "; ".join(control.cci_refs),
                    "References": "; ".join(control.references),
                    "Tags": "; ".join(control.tags),
                    "Raw ID": control.raw_id,
                }
            )


def write_controls_json(document: StigDocument, path: str | Path) -> None:
    ensure_parent(path)
    payload = asdict(document)
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


BACKLOG_FIELDS = [
    "Title",
    "Vuln ID",
    "Rule ID",
    "Severity",
    "Change Type",
    "Impact",
    "Suggested Owner",
    "Tags",
    "Why It Matters",
    "Check Summary",
    "Fix Summary",
    "Evidence Needed",
    "Status",
    "Notes",
]


def write_backlog_csv(changes: Iterable[ControlChange], path: str | Path, config: StigPilotConfig | None = None) -> None:
    ensure_parent(path)
    with Path(path).open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=BACKLOG_FIELDS)
        writer.writeheader()
        for change in changes:
            writer.writerow(backlog_row(change, config))


def backlog_row(change: ControlChange, config: StigPilotConfig | None = None) -> dict[str, str]:
    control = change.current_control or StigControl()
    return {
        "Title": control.title,
        "Vuln ID": control.vuln_id or change.vuln_id,
        "Rule ID": control.rule_id or change.rule_id,
        "Severity": control.severity,
        "Change Type": change.change_type,
        "Impact": change.impact,
        "Suggested Owner": suggested_owner(control, config),
        "Tags": "; ".join(control.tags),
        "Why It Matters": change.reason,
        "Check Summary": summarize(control.check_text),
        "Fix Summary": summarize(control.fix_text),
        "Evidence Needed": "; ".join(evidence_requests(control)),
        "Status": "Not Started",
        "Notes": "",
    }


def write_ticket_csv(controls: Iterable[StigControl], path: str | Path, config: StigPilotConfig | None = None) -> None:
    ensure_parent(path)
    fields = [
        "Title",
        "Vuln ID",
        "Rule ID",
        "Severity",
        "Suggested Owner",
        "Tags",
        "Ticket Summary",
        "Description",
        "Evidence Needed",
        "Status",
        "Notes",
    ]
    with Path(path).open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for control in controls:
            writer.writerow(
                {
                    "Title": control.title,
                    "Vuln ID": control.vuln_id,
                    "Rule ID": control.rule_id,
                    "Severity": control.severity,
                    "Suggested Owner": suggested_owner(control, config),
                    "Tags": "; ".join(control.tags),
                    "Ticket Summary": f"Review STIG control {control.vuln_id or control.rule_id}: {control.title}",
                    "Description": summarize(f"Check: {control.check_text} Fix: {control.fix_text}", 500),
                    "Evidence Needed": "; ".join(evidence_requests(control)),
                    "Status": "Not Started",
                    "Notes": "",
                }
            )


def write_jira_csv(changes: Iterable[ControlChange], path: str | Path, config: StigPilotConfig | None = None) -> None:
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
                    "Assignee": suggested_owner(control, config),
                    "Description": _ticket_description(change, config),
                }
            )


def write_servicenow_csv(changes: Iterable[ControlChange], path: str | Path, config: StigPilotConfig | None = None) -> None:
    """Write a ServiceNow-friendly local CSV."""

    ensure_parent(path)
    fields = ["short_description", "description", "assignment_group", "priority", "u_stig_vuln_id", "u_stig_rule_id", "u_stig_impact", "u_stig_tags"]
    with Path(path).open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for change in changes:
            control = change.current_control or StigControl()
            writer.writerow(
                {
                    "short_description": f"Review STIG change {control.vuln_id or control.rule_id}: {control.title}",
                    "description": _ticket_description(change, config),
                    "assignment_group": suggested_owner(control, config),
                    "priority": _priority(change),
                    "u_stig_vuln_id": control.vuln_id or change.vuln_id,
                    "u_stig_rule_id": control.rule_id or change.rule_id,
                    "u_stig_impact": change.impact,
                    "u_stig_tags": "; ".join(control.tags),
                }
            )


def github_issue_markdown(changes: Iterable[ControlChange], config: StigPilotConfig | None = None) -> str:
    """Generate copy/paste-ready GitHub issue Markdown sections."""

    lines = ["# STIGPilot GitHub Issue Drafts", ""]
    for idx, change in enumerate(changes, start=1):
        control = change.current_control or StigControl()
        lines.extend(
            [
                f"## Issue {idx}",
                "",
                f"Title: `{change.change_type}: {control.vuln_id or control.rule_id} - {control.title}`",
                "",
                f"Labels: `stigpilot`, `{change.impact}`, " + ", ".join(f"`{tag}`" for tag in control.tags),
                "",
                "### Context",
                "",
                f"- Severity: {control.severity or 'unspecified'}",
                f"- Suggested owner: {suggested_owner(control, config)}",
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
        lines.extend(
            [
                "",
                "### Acceptance Criteria",
                "",
                "- [ ] Change reviewed by suggested owner",
                "- [ ] Ticket priority matches STIGPilot impact category",
                "- [ ] Evidence request updated or confirmed unchanged",
                "- [ ] Notes added for any downstream checklist or backlog impact",
                "",
                "### Notes",
                "",
                "- ",
                "",
            ]
        )
    return "\n".join(lines)


def _ticket_description(change: ControlChange, config: StigPilotConfig | None = None) -> str:
    control = change.current_control or StigControl()
    return "\n".join(
        [
            f"Change type: {change.change_type}",
            f"Impact: {change.impact}",
            f"Reason: {change.reason}",
            f"Changed fields: {', '.join(change.changed_fields) or change.change_type}",
            f"Vuln ID: {control.vuln_id or change.vuln_id}",
            f"Rule ID: {control.rule_id or change.rule_id}",
            f"Suggested owner: {suggested_owner(control, config)}",
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
