"""Markdown report generation."""

from __future__ import annotations

from collections import Counter
from collections import defaultdict
from pathlib import Path

from .config import StigPilotConfig
from .impact import evidence_requests
from .models import ControlChange, StigControl, StigDocument
from .taxonomy import suggested_owner
from .utils import ensure_parent, summarize


IMPACT_LABELS = {
    "high_priority_review": "High-priority review",
    "implementation_change_likely": "Implementation change likely",
    "evidence_update_likely": "Evidence update likely",
    "review_recommended": "Review recommended",
    "no_action_likely": "No action likely",
}


IMPACT_MEANINGS = {
    "high_priority_review": "Review first because severity or new high-risk scope changed.",
    "implementation_change_likely": "Remediation steps may need updates before reusing old tickets.",
    "evidence_update_likely": "Check procedure changed enough that evidence requests may need refresh.",
    "review_recommended": "Traceability, cleanup, or analyst review is recommended.",
    "no_action_likely": "Likely wording or metadata only; keep awareness but avoid noisy tickets.",
}


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
    top = priority_changes(changes)[:10]
    lines = [
        "# STIGPilot Change Brief",
        "",
        "## Executive Summary",
        "",
        executive_summary(changes, config),
        "",
        "## Source Files",
        "",
        f"Old source: `{Path(old_doc.source_file).name}`",
        f"New source: `{Path(new_doc.source_file).name}`",
        f"Total controls old: {len(old_doc.controls)}",
        f"Total controls new: {len(new_doc.controls)}",
        "",
        "## At-a-Glance",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Added controls | {counts.get('added', 0)} |",
        f"| Removed controls | {counts.get('removed', 0)} |",
        f"| Modified controls | {sum(1 for change in changes if change.change_type not in {'added', 'removed'})} |",
        f"| Severity changes | {severity_changed_count} |",
        f"| High-priority review | {impacts.get('high_priority_review', 0)} |",
        f"| Implementation change likely | {impacts.get('implementation_change_likely', 0)} |",
        f"| Evidence update likely | {impacts.get('evidence_update_likely', 0)} |",
        "",
        "## Priority Actions",
        "",
    ]
    if not top:
        lines.append("- No high-priority implementation or evidence changes detected.")
    for idx, change in enumerate(top, start=1):
        control = change.current_control or StigControl()
        owner = suggested_owner(control, config)
        control_id = control.vuln_id or control.rule_id or "Control"
        lines.append(
            f"{idx}. **{control_id} - {control.title or 'Untitled'}**"
        )
        lines.append(f"   - Impact: {impact_label(change.impact)}")
        lines.append(f"   - Owner: {owner}")
        lines.append(f"   - Why it matters: {change.reason}")
    lines.extend(
        [
            "",
            "## Owner Impact",
            "",
            "| Owner | Changes | High Priority | Implementation Likely | Evidence Updates |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for owner, owner_changes in owner_groups(changes, config).items():
        owner_impacts = Counter(change.impact for change in owner_changes)
        lines.append(
            f"| {_md(owner)} | {len(owner_changes)} | {owner_impacts.get('high_priority_review', 0)} | "
            f"{owner_impacts.get('implementation_change_likely', 0)} | {owner_impacts.get('evidence_update_likely', 0)} |"
        )
    lines.extend(
        [
            "",
            "## Change Categories",
            "",
            "| Impact | Count | Meaning |",
            "| --- | ---: | --- |",
        ]
    )
    for impact, meaning in IMPACT_MEANINGS.items():
        lines.append(f"| {impact_label(impact)} | {impacts.get(impact, 0)} | {meaning} |")
    lines.extend(
        [
            "",
            "## Top Changed Controls",
            "",
            "| Impact | Severity | Vuln ID | Rule ID | Title | Owner | Why it matters |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for change in top:
        control = change.current_control or StigControl()
        lines.append(
            f"| {impact_label(change.impact)} | {control.severity or 'unspecified'} | {control.vuln_id or change.vuln_id} | "
            f"{control.rule_id or change.rule_id} | {_md(control.title)} | {suggested_owner(control, config)} | {_md(change.reason)} |"
        )
    lines.extend(
        [
            "",
            "## Detailed Changes",
            "",
            "| Change Type | Impact | Severity | Vuln ID | Rule ID | Changed Fields | Owner | Why it matters |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for change in changes:
        control = change.current_control or StigControl()
        lines.append(
            f"| {change.change_type} | {impact_label(change.impact)} | {control.severity or 'unspecified'} | "
            f"{control.vuln_id or change.vuln_id} | {control.rule_id or change.rule_id} | "
            f"{', '.join(change.changed_fields) or '-'} | {suggested_owner(control, config)} | {_md(change.reason)} |"
        )
    return "\n".join(lines) + "\n"


def executive_summary(changes: list[ControlChange], config: StigPilotConfig | None = None) -> str:
    if not changes:
        return "No STIG control changes were detected between the compared files. No remediation or evidence refresh work is suggested by this comparison."
    impacts = Counter(change.impact for change in changes)
    owners = owner_groups(changes, config)
    owner_phrase = ", ".join(list(owners.keys())[:3]) if owners else "no owner group"
    action_count = impacts.get("high_priority_review", 0) + impacts.get("implementation_change_likely", 0) + impacts.get("evidence_update_likely", 0)
    return (
        f"{len(changes)} control change(s) were detected. "
        f"{action_count} change(s) are likely to require priority review, implementation work, or evidence refresh. "
        f"The most affected owner group(s) are {owner_phrase}. "
        "Prioritize high-severity additions or severity increases, then review remediation text changes before reusing old tickets."
    )


def priority_changes(changes: list[ControlChange]) -> list[ControlChange]:
    priority = {"high_priority_review": 0, "implementation_change_likely": 1, "evidence_update_likely": 2, "review_recommended": 3, "no_action_likely": 4}
    return sorted(changes, key=lambda change: (priority.get(change.impact, 9), change.current_control.severity if change.current_control else "", change.vuln_id))


def owner_groups(changes: list[ControlChange], config: StigPilotConfig | None = None) -> dict[str, list[ControlChange]]:
    grouped: dict[str, list[ControlChange]] = defaultdict(list)
    for change in changes:
        grouped[suggested_owner(change.current_control, config)].append(change)
    return dict(sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])))


def change_summary_counts(changes: list[ControlChange]) -> dict[str, int]:
    impacts = Counter(change.impact for change in changes)
    return {
        "total": len(changes),
        "added": sum(1 for change in changes if change.change_type == "added"),
        "removed": sum(1 for change in changes if change.change_type == "removed"),
        "modified": sum(1 for change in changes if change.change_type not in {"added", "removed"}),
        "severity_changed": sum(1 for change in changes if "severity" in change.changed_fields),
        "high_priority_review": impacts.get("high_priority_review", 0),
        "implementation_change_likely": impacts.get("implementation_change_likely", 0),
        "evidence_update_likely": impacts.get("evidence_update_likely", 0),
    }


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
        executive_summary(changes, config),
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
        "| Owner | Changes | High Priority | Implementation Likely | Evidence Updates |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    if owners:
        for owner, count in owners.most_common():
            owner_changes = [change for change in changes if suggested_owner(change.current_control, config) == owner]
            owner_impacts = Counter(change.impact for change in owner_changes)
            lines.append(
                f"| {_md(owner)} | {count} | {owner_impacts.get('high_priority_review', 0)} | "
                f"{owner_impacts.get('implementation_change_likely', 0)} | {owner_impacts.get('evidence_update_likely', 0)} |"
            )
    else:
        lines.append("- No owner impact detected.")

    lines.extend(["", "## Top Actions", ""])
    if not priority_changes:
        lines.append("- No high-priority implementation or evidence actions were detected.")
    for change in priority_changes:
        control = change.current_control or StigControl()
        lines.append(
            f"- {control.vuln_id or control.rule_id or 'Control'}: {control.title or 'Untitled'} "
            f"({impact_label(change.impact)}; {suggested_owner(control, config)})"
        )

    lines.extend(
        [
            "",
            "## Recommended Next Steps",
            "",
            "- Assign high-priority and implementation-likely changes to the suggested owner groups.",
            "- Use the remediation backlog CSV for ticket import or queue grooming.",
            "- Use the evidence checklist to refresh validation requests where check guidance changed.",
            "",
            "## Assumptions and Limitations",
            "",
            "- This is change triage and remediation planning support, not formal compliance validation.",
            "- Official DISA tooling and organizational review remain authoritative.",
            "- Owner and impact suggestions are transparent keyword/rule matches and should be reviewed by the team.",
        ]
    )
    return "\n".join(lines) + "\n"


def evidence_checklist(document: StigDocument, severity: str | None = None, config: StigPilotConfig | None = None) -> str:
    controls = filter_by_severity(document.controls, severity)
    grouped: dict[str, list[StigControl]] = defaultdict(list)
    for control in controls:
        grouped[suggested_owner(control, config)].append(control)
    lines = [
        "# STIGPilot Evidence Checklist",
        "",
        f"Source: `{Path(document.source_file).name}`",
        f"Controls included: {len(controls)}",
        "",
    ]
    for owner in sorted(grouped):
        lines.extend([f"## {owner}", ""])
        for control in grouped[owner]:
            lines.extend(
                [
                    f"### {control.vuln_id or control.rule_id or 'Control'} - {control.title or 'Untitled'}",
                    "",
                    f"- Severity: {control.severity or 'unspecified'}",
                    f"- Rule ID: {control.rule_id or 'unknown'}",
                    f"- Tags: {', '.join(control.tags)}",
                    f"- Check summary: {summarize(control.check_text)}",
                    "",
                    "Validation metadata:",
                    "",
                    "- [ ] Asset/System:",
                    "- [ ] Environment:",
                    "- [ ] Validated by:",
                    "- [ ] Date:",
                    "- [ ] Notes:",
                    "",
                    "Evidence requested:",
                ]
            )
            for request in evidence_requests(control):
                lines.append(f"- [ ] {request}")
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


def impact_label(value: str) -> str:
    return IMPACT_LABELS.get(value, value.replace("_", " ").title())
