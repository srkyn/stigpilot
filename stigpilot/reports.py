"""Markdown report generation."""

from __future__ import annotations

from collections import Counter
from collections import defaultdict
from html import escape
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


def html_change_brief(
    old_doc: StigDocument,
    new_doc: StigDocument,
    changes: list[ControlChange],
    config: StigPilotConfig | None = None,
) -> str:
    """Generate a self-contained HTML change brief for browser sharing."""

    counts = change_summary_counts(changes)
    top = priority_changes(changes)[:10]
    owner_rows = []
    for owner, owner_changes in owner_groups(changes, config).items():
        owner_impacts = Counter(change.impact for change in owner_changes)
        owner_rows.append(
            [
                owner,
                str(len(owner_changes)),
                str(owner_impacts.get("high_priority_review", 0)),
                str(owner_impacts.get("implementation_change_likely", 0)),
                str(owner_impacts.get("evidence_update_likely", 0)),
            ]
        )

    metric_rows = [
        ("Added controls", counts["added"]),
        ("Removed controls", counts["removed"]),
        ("Modified controls", counts["modified"]),
        ("Severity changes", counts["severity_changed"]),
        ("High-priority review", counts["high_priority_review"]),
        ("Implementation change likely", counts["implementation_change_likely"]),
        ("Evidence update likely", counts["evidence_update_likely"]),
    ]
    category_rows = [
        [impact_label(impact), str(Counter(change.impact for change in changes).get(impact, 0)), meaning]
        for impact, meaning in IMPACT_MEANINGS.items()
    ]
    top_rows = [_change_table_row(change, config) for change in top]
    detail_rows = [
        [
            change.change_type,
            impact_label(change.impact),
            (change.current_control or StigControl()).severity or "unspecified",
            (change.current_control or StigControl()).vuln_id or change.vuln_id,
            (change.current_control or StigControl()).rule_id or change.rule_id,
            ", ".join(change.changed_fields) or "-",
            suggested_owner(change.current_control, config),
            change.reason,
        ]
        for change in changes
    ]
    priority_items = "".join(
        f"<li><strong>{escape((change.current_control or StigControl()).vuln_id or change.vuln_id or 'Control')} - "
        f"{escape((change.current_control or StigControl()).title or 'Untitled')}</strong>"
        f"<span>{escape(impact_label(change.impact))} | {escape(suggested_owner(change.current_control, config))}</span>"
        f"<p>{escape(change.reason)}</p></li>"
        for change in top
    ) or "<li>No high-priority implementation or evidence changes detected.</li>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>STIGPilot Change Brief</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --ink: #0f172a;
      --muted: #475569;
      --line: #dbe3ef;
      --blue: #0369a1;
      --green: #15803d;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.5;
    }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 40px 24px 64px;
    }}
    header {{
      border-left: 6px solid var(--blue);
      padding: 4px 0 4px 20px;
      margin-bottom: 28px;
    }}
    h1 {{ margin: 0 0 8px; font-size: 38px; }}
    h2 {{ margin-top: 34px; font-size: 23px; }}
    .meta, .summary {{ color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin: 22px 0;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px;
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
    }}
    .metric {{ font-size: 30px; font-weight: 700; color: var(--blue); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      overflow: hidden;
      margin-top: 12px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{ background: #eaf2fb; color: #123047; }}
    tr:last-child td {{ border-bottom: 0; }}
    ol.priority {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px 24px 16px 42px;
    }}
    ol.priority li {{ margin: 0 0 14px; }}
    ol.priority span {{
      display: block;
      color: var(--green);
      font-weight: 700;
      margin-top: 3px;
    }}
    ol.priority p {{ margin: 4px 0 0; color: var(--muted); }}
    footer {{
      margin-top: 40px;
      color: var(--muted);
      font-size: 13px;
    }}
  </style>
</head>
<body>
<main>
  <header>
    <h1>STIGPilot Change Brief</h1>
    <div class="meta">Old: {escape(Path(old_doc.source_file).name)} | New: {escape(Path(new_doc.source_file).name)}</div>
    <div class="meta">Old controls: {len(old_doc.controls)} | New controls: {len(new_doc.controls)}</div>
  </header>
  <section class="card summary">{escape(executive_summary(changes, config))}</section>
  <section class="grid">
    {_metric_cards(metric_rows)}
  </section>
  <h2>Priority Actions</h2>
  <ol class="priority">{priority_items}</ol>
  <h2>Owner Impact</h2>
  {_html_table(["Owner", "Changes", "High Priority", "Implementation Likely", "Evidence Updates"], owner_rows)}
  <h2>Change Categories</h2>
  {_html_table(["Impact", "Count", "Meaning"], category_rows)}
  <h2>Top Changed Controls</h2>
  {_html_table(["Impact", "Severity", "Vuln ID", "Rule ID", "Title", "Owner", "Why it matters"], top_rows)}
  <h2>Detailed Changes</h2>
  {_html_table(["Change Type", "Impact", "Severity", "Vuln ID", "Rule ID", "Changed Fields", "Owner", "Why it matters"], detail_rows)}
  <footer>
    Generated by STIGPilot. This is change triage and remediation planning support, not formal compliance validation.
  </footer>
</main>
</body>
</html>
"""


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


def _change_table_row(change: ControlChange, config: StigPilotConfig | None = None) -> list[str]:
    control = change.current_control or StigControl()
    return [
        impact_label(change.impact),
        control.severity or "unspecified",
        control.vuln_id or change.vuln_id,
        control.rule_id or change.rule_id,
        control.title,
        suggested_owner(control, config),
        change.reason,
    ]


def _metric_cards(rows: list[tuple[str, int]]) -> str:
    return "\n".join(
        f'<div class="card"><div class="metric">{count}</div><div>{escape(label)}</div></div>'
        for label, count in rows
    )


def _html_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        column_count = len(headers)
        rows = [["No matching records."] + [""] * (column_count - 1)]
    header_html = "".join(f"<th>{escape(header)}</th>" for header in headers)
    row_html = "\n".join(
        "<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{header_html}</tr></thead><tbody>{row_html}</tbody></table>"
