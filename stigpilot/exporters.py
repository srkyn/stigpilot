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

IMPACT_LABELS = {
    "high_priority_review": "High-priority review",
    "implementation_change_likely": "Implementation change likely",
    "evidence_update_likely": "Evidence update likely",
    "review_recommended": "Review recommended",
    "no_action_likely": "No action likely",
}
CHANGES_JSON_SCHEMA_VERSION = "1.0"
SEVERITY_EMOJI = {"high": "🔴", "medium": "🟡", "low": "🔵"}
IMPACT_EMOJI = {
    "high_priority_review": "🔴",
    "implementation_change_likely": "🟡",
    "evidence_update_likely": "🟡",
    "review_recommended": "🔵",
    "no_action_likely": "⚪",
}


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


def write_changes_json(
    changes: Iterable[ControlChange],
    path: str | Path,
    old_doc: StigDocument | None = None,
    new_doc: StigDocument | None = None,
    config: StigPilotConfig | None = None,
) -> None:
    """Write machine-readable change intelligence for automation workflows."""

    ensure_parent(path)
    change_list = list(changes)
    payload = {
        "schema_version": CHANGES_JSON_SCHEMA_VERSION,
        "schema": "docs/schemas/changes.schema.json",
        "source": {
            "old_file": old_doc.source_file if old_doc else "",
            "new_file": new_doc.source_file if new_doc else "",
            "old_title": old_doc.title if old_doc else "",
            "new_title": new_doc.title if new_doc else "",
            "old_version": old_doc.version if old_doc else "",
            "new_version": new_doc.version if new_doc else "",
            "old_release": old_doc.release if old_doc else "",
            "new_release": new_doc.release if new_doc else "",
            "old_control_count": len(old_doc.controls) if old_doc else 0,
            "new_control_count": len(new_doc.controls) if new_doc else 0,
        },
        "summary": _change_counts(change_list),
        "changes": [_change_json_row(change, config) for change in change_list],
    }
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
                f"- Severity: {_severity_display(control.severity)}",
                f"- Suggested owner: {suggested_owner(control, config)}",
                f"- Impact: {_impact_display(change.impact)} (`{change.impact}`)",
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


def remediation_draft_markdown(changes: Iterable[ControlChange], config: StigPilotConfig | None = None) -> str:
    """Generate review-only remediation draft notes without executable steps."""

    lines = [
        "# STIGPilot Remediation Drafts",
        "",
        "> Review-only planning notes. STIGPilot does not apply changes, run commands, edit policy, restart services, or modify hosts.",
        "",
        "Use these drafts to prepare owner review, change-control notes, implementation tickets, and evidence requests. Validate every item against the local environment before any change is made.",
        "",
    ]
    for idx, change in enumerate(changes, start=1):
        control = change.current_control or StigControl()
        draft_note = _remediation_draft_note(change, control)
        review_items = _remediation_review_items(change)
        lines.extend(
            [
                f"## Draft {idx}: {control.vuln_id or change.vuln_id or control.rule_id or change.rule_id}",
                "",
                f"**Title:** {control.title or 'Untitled control'}",
                f"**Impact:** {_impact_display(change.impact)} (`{change.impact or 'unclassified'}`)",
                f"**Suggested owner:** {suggested_owner(control, config)}",
                f"**Change type:** {change.change_type}",
                f"**Why it matters:** {change.reason or 'Review the changed control text before reusing prior implementation notes.'}",
                "",
                "### Draft Remediation Note",
                "",
                draft_note,
                "",
                "### Review Before Action",
                "",
            ]
        )
        lines.extend(f"- [ ] {item}" for item in review_items)
        lines.extend(
            [
                "",
                "### Evidence To Prepare",
                "",
            ]
        )
        for item in evidence_requests(control):
            lines.append(f"- [ ] {item}")
        lines.extend(
            [
                "",
                "### Boundary",
                "",
                "- Changes made by STIGPilot: none.",
                "- This draft is not an executable patch.",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _remediation_draft_note(change: ControlChange, control: StigControl) -> str:
    if change.change_type == "removed":
        return "The control was removed from the compared release. Review downstream tickets, evidence requests, mappings, and local exceptions before closing or archiving related work."
    return summarize(control.fix_text, 700) or "Review the current STIG fix text and document the local implementation path."


def _remediation_review_items(change: ControlChange) -> list[str]:
    if change.change_type == "removed":
        return [
            "Confirm the control is actually removed from the authoritative release being adopted.",
            "Review open tickets, evidence requests, mappings, and exceptions tied to the removed control.",
            "Decide whether any local policy still requires the control despite the STIG removal.",
            "Document the closure, carry-forward, or exception decision.",
            "Do not remove a local control solely because it disappeared from one comparison packet.",
        ]
    return [
        "Confirm the control applies to the local environment.",
        "Identify the actual implementation path: local policy, GPO, MDM, configuration management, image build, or compensating control.",
        "Test in a safe scope before broad rollout.",
        "Document rollback or exception handling.",
        "Update evidence only after the approved implementation path is confirmed.",
    ]


def _ticket_description(change: ControlChange, config: StigPilotConfig | None = None) -> str:
    control = change.current_control or StigControl()
    return "\n".join(
        [
            f"Change type: {change.change_type}",
            f"Impact: {_impact_label(change.impact)} ({change.impact})",
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


def _impact_label(value: str) -> str:
    return IMPACT_LABELS.get(value, value.replace("_", " ").title())


def _impact_display(value: str) -> str:
    return f"{IMPACT_EMOJI.get(value, '⚪')} {_impact_label(value)}"


def _severity_display(value: str) -> str:
    label = (value or "unspecified").upper()
    return f"{SEVERITY_EMOJI.get((value or '').lower(), '⚪')} {label}"


def _change_counts(changes: list[ControlChange]) -> dict[str, int]:
    impacts: dict[str, int] = {}
    change_types: dict[str, int] = {}
    for change in changes:
        impacts[change.impact] = impacts.get(change.impact, 0) + 1
        change_types[change.change_type] = change_types.get(change.change_type, 0) + 1
    return {
        "total": len(changes),
        "added": change_types.get("added", 0),
        "removed": change_types.get("removed", 0),
        "modified": sum(1 for change in changes if change.change_type not in {"added", "removed"}),
        "severity_changed": sum(1 for change in changes if "severity" in change.changed_fields),
        "high_priority_review": impacts.get("high_priority_review", 0),
        "implementation_change_likely": impacts.get("implementation_change_likely", 0),
        "evidence_update_likely": impacts.get("evidence_update_likely", 0),
    }


def _change_json_row(change: ControlChange, config: StigPilotConfig | None = None) -> dict[str, object]:
    control = change.current_control or StigControl()
    return {
        "change_type": change.change_type,
        "impact": change.impact,
        "impact_label": _impact_label(change.impact),
        "reason": change.reason,
        "changed_fields": change.changed_fields,
        "suggested_owner": suggested_owner(control, config),
        "evidence_needed": evidence_requests(control),
        "control": {
            "title": control.title,
            "vuln_id": control.vuln_id or change.vuln_id,
            "rule_id": control.rule_id or change.rule_id,
            "group_id": control.group_id,
            "stig_id": control.stig_id,
            "severity": control.severity,
            "tags": control.tags,
            "cci_refs": control.cci_refs,
            "references": control.references,
            "check_summary": summarize(control.check_text),
            "fix_summary": summarize(control.fix_text),
        },
    }
