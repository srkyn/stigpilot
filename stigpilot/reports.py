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
SEVERITY_EMOJI = {
    "high": "🔴",
    "HIGH": "🔴",
    "medium": "🟡",
    "MEDIUM": "🟡",
    "low": "🔵",
    "LOW": "🔵",
}
IMPACT_EMOJI = {
    "high_priority_review": "🔴",
    "High-priority review": "🔴",
    "implementation_change_likely": "🟡",
    "Implementation change likely": "🟡",
    "evidence_update_likely": "🟡",
    "Evidence update likely": "🟡",
    "review_recommended": "🔵",
    "Review recommended": "🔵",
    "no_action_likely": "⚪",
    "No action likely": "⚪",
}
SEVERITY_BADGES = {
    "high": '<span class="badge badge-high">HIGH</span>',
    "medium": '<span class="badge badge-medium">MEDIUM</span>',
    "low": '<span class="badge badge-low">LOW</span>',
}
IMPACT_BADGES = {
    "high_priority_review": '<span class="badge badge-high">High-priority review</span>',
    "High-priority review": '<span class="badge badge-high">High-priority review</span>',
    "implementation_change_likely": '<span class="badge badge-amber">Implementation change likely</span>',
    "Implementation change likely": '<span class="badge badge-amber">Implementation change likely</span>',
    "evidence_update_likely": '<span class="badge badge-amber">Evidence update likely</span>',
    "Evidence update likely": '<span class="badge badge-amber">Evidence update likely</span>',
    "review_recommended": '<span class="badge badge-blue">Review recommended</span>',
    "Review recommended": '<span class="badge badge-blue">Review recommended</span>',
    "no_action_likely": '<span class="badge badge-muted">No action likely</span>',
    "No action likely": '<span class="badge badge-muted">No action likely</span>',
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
            f"| {severity_display(control.severity or 'unspecified')} | {control.vuln_id or ''} | {control.rule_id or ''} | "
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
        risk_statement(changes),
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        executive_summary(changes, config),
        "",
        "---",
        "",
        "## Source Files",
        "",
        f"Old source: `{Path(old_doc.source_file).name}`",
        f"New source: `{Path(new_doc.source_file).name}`",
        f"Total controls old: {len(old_doc.controls)}",
        f"Total controls new: {len(new_doc.controls)}",
        "",
        "---",
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
        "---",
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
        lines.append(f"### {idx}. {impact_display(change.impact)} {control_id} — {control.title or 'Untitled'}")
        lines.append("")
        lines.append(f"**Impact:** {impact_label(change.impact)} · **Owner:** {owner}")
        lines.append("")
        lines.append(change.reason)
        lines.append("")
    lines.extend(
        [
            "",
            "---",
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
            "---",
            "",
            "## Change Categories",
            "",
            "| Impact | Count | Meaning |",
            "| --- | ---: | --- |",
        ]
    )
    for impact, meaning in IMPACT_MEANINGS.items():
        lines.append(f"| {impact_display(impact)} | {impacts.get(impact, 0)} | {meaning} |")
    lines.extend(
        [
            "",
            "---",
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
            f"| {impact_display(change.impact)} | {severity_display(control.severity or 'unspecified')} | {control.vuln_id or change.vuln_id} | "
            f"{control.rule_id or change.rule_id} | {_md(control.title)} | {suggested_owner(control, config)} | {_md(change.reason)} |"
        )
    lines.extend(
        [
            "",
            "---",
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
            f"| {change.change_type} | {impact_display(change.impact)} | {severity_display(control.severity or 'unspecified')} | "
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
        [html_impact_badge(impact), str(Counter(change.impact for change in changes).get(impact, 0)), meaning]
        for impact, meaning in IMPACT_MEANINGS.items()
    ]
    top_rows = [_change_table_row(change, config) for change in top]
    detail_rows = [
        [
            change.change_type,
            html_impact_badge(change.impact),
            html_severity_badge((change.current_control or StigControl()).severity or "unspecified"),
            (change.current_control or StigControl()).vuln_id or change.vuln_id,
            (change.current_control or StigControl()).rule_id or change.rule_id,
            ", ".join(change.changed_fields) or "-",
            suggested_owner(change.current_control, config),
            change.reason,
        ]
        for change in changes
    ]
    priority_items = "".join(_priority_card(idx, change, config) for idx, change in enumerate(top, start=1))
    if not priority_items:
        priority_items = '<div class="priority-card priority-low"><div class="priority-body">No high-priority implementation or evidence changes detected.</div></div>'
    doc_risk = risk_level(changes).lower()
    priority_count = counts["high_priority_review"] + counts["implementation_change_likely"] + counts["evidence_update_likely"]
    stig_name = new_doc.title or old_doc.title or "STIG comparison"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>STIGPilot Change Brief</title>
  <!-- Optional web font. Requires internet access; system font fallback is used offline. -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #f8fafc; --surface: #ffffff; --surface-2: #f1f5f9; --ink: #0f172a; --ink-2: #334155; --ink-3: #64748b; --line: #e2e8f0; --line-2: #cbd5e1;
      --blue-50: #eff6ff; --blue-100: #dbeafe; --blue-600: #2563eb; --blue-700: #1d4ed8; --blue-900: #1e3a5f;
      --red-50: #fef2f2; --red-100: #fee2e2; --red-600: #dc2626; --red-700: #b91c1c; --red-900: #7f1d1d;
      --amber-50: #fffbeb; --amber-100: #fef3c7; --amber-600: #d97706; --amber-700: #b45309; --amber-900: #78350f;
      --green-50: #f0fdf4; --green-100: #dcfce7; --green-600: #16a34a; --green-900: #14532d;
      --slate-50: #f8fafc; --slate-100: #f1f5f9; --slate-200: #e2e8f0; --slate-600: #475569; --slate-900: #0f172a;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #0f172a; --surface: #1e293b; --surface-2: #0f172a; --ink: #f1f5f9; --ink-2: #cbd5e1; --ink-3: #94a3b8; --line: #334155; --line-2: #475569;
        --blue-50: #1e3a5f; --blue-100: #1e40af; --blue-600: #60a5fa; --blue-700: #93c5fd;
        --red-50: #450a0a; --red-100: #7f1d1d; --red-600: #f87171; --red-700: #fca5a5;
        --amber-50: #451a03; --amber-100: #78350f; --amber-600: #fbbf24; --amber-700: #fcd34d;
        --green-50: #052e16; --green-100: #14532d; --green-600: #4ade80;
        --slate-50: #1e293b; --slate-100: #334155; --slate-200: #475569; --slate-600: #94a3b8; --slate-900: #f1f5f9;
      }}
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      line-height: 1.5;
    }}
    .doc-nav {{ position: sticky; top: 0; background: var(--surface); border-bottom: 0.5px solid var(--line); padding: 10px 24px; display: flex; gap: 20px; align-items: center; font-size: 13px; z-index: 10; }}
    .doc-nav a {{ color: var(--blue-600); text-decoration: none; }}
    .doc-nav a:hover {{ text-decoration: underline; }}
    .nav-label {{ color: var(--ink-3); font-weight: 500; }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 40px 24px 64px;
    }}
    header {{
      padding: 0 0 18px;
      margin-bottom: 28px;
    }}
    .header-eyebrow {{ color: var(--ink-3); font-size: 12px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; }}
    .header-title {{ margin: 8px 0; font-size: 34px; line-height: 1.15; font-weight: 600; }}
    .header-meta, .summary {{ color: var(--ink-3); }}
    .risk-bar {{ height: 4px; margin-top: 18px; background: var(--green-600); }}
    .risk-bar[data-risk="high"] {{ background: var(--red-600); }}
    .risk-bar[data-risk="medium"] {{ background: var(--amber-600); }}
    h2 {{ margin-top: 34px; font-size: 21px; font-weight: 600; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(185px, 1fr)); gap: 12px; margin: 22px 0; }}
    .card {{ background: var(--surface); border: 0.5px solid var(--line); border-radius: 10px; padding: 16px; }}
    .metric {{ font-size: 32px; font-weight: 600; color: var(--ink-2); }}
    .metric-label {{ font-size: 13px; color: var(--ink-3); }}
    .metric-high {{ border-left: 4px solid var(--red-100); }} .metric-high .metric {{ color: var(--red-600); }}
    .metric-amber {{ border-left: 4px solid var(--amber-100); }} .metric-amber .metric {{ color: var(--amber-600); }}
    .metric-blue {{ border-left: 4px solid var(--blue-100); }} .metric-blue .metric {{ color: var(--blue-600); }}
    .metric-zero .metric {{ color: var(--ink-3); }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; letter-spacing: 0.03em; white-space: nowrap; }}
    .badge-high {{ background: var(--red-100); color: var(--red-900); }} .badge-amber {{ background: var(--amber-100); color: var(--amber-900); }}
    .badge-blue {{ background: var(--blue-100); color: var(--blue-900); }} .badge-low, .badge-muted {{ background: var(--slate-100); color: var(--slate-600); }}
    .badge-medium {{ background: var(--amber-100); color: var(--amber-900); }} .badge-owner {{ background: var(--surface-2); color: var(--ink-2); border: 0.5px solid var(--line); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--surface); border: 0.5px solid var(--line); border-radius: 10px; overflow: hidden; font-size: 13.5px; line-height: 1.5; }}
    th {{ background: var(--surface-2); color: var(--ink-2); font-weight: 500; font-size: 12px; letter-spacing: 0.04em; text-transform: uppercase; padding: 10px 14px; border-bottom: 0.5px solid var(--line); text-align: left; }}
    td {{ padding: 11px 14px; border-bottom: 0.5px solid var(--line); color: var(--ink); vertical-align: middle; }}
    tr:last-child td {{ border-bottom: none; }} tr:hover td {{ background: var(--surface-2); }}
    .priority-card {{ border: 0.5px solid var(--line); border-radius: 10px; background: var(--surface); margin-bottom: 10px; overflow: hidden; }}
    .priority-card.priority-high {{ border-left: 4px solid var(--red-600); }} .priority-card.priority-medium {{ border-left: 4px solid var(--amber-600); }} .priority-card.priority-low {{ border-left: 4px solid var(--blue-600); }}
    .priority-header {{ display: flex; align-items: center; gap: 12px; padding: 12px 16px; border-bottom: 0.5px solid var(--line); }}
    .priority-number {{ font-size: 13px; font-weight: 600; color: var(--ink-3); min-width: 20px; }}
    .priority-vuln-id {{ font-size: 11px; font-family: monospace; color: var(--ink-3); display: block; }}
    .priority-title {{ font-size: 14px; font-weight: 500; color: var(--ink); }}
    .priority-badges {{ margin-left: auto; display: flex; gap: 6px; flex-shrink: 0; }}
    .priority-body {{ padding: 10px 16px 12px; font-size: 13.5px; color: var(--ink-2); line-height: 1.6; }}
    footer {{
      margin-top: 40px;
      color: var(--ink-3);
      font-size: 13px;
    }}
    @media print {{
      .doc-nav {{ display: none; }}
      body {{ background: white; color: black; font-size: 11pt; }}
      main {{ max-width: 100%; padding: 0; }}
      .priority-card {{ box-shadow: none; border: 0.5px solid #ccc; page-break-inside: avoid; }}
      table {{ box-shadow: none; }}
      h2 {{ page-break-after: avoid; }}
      thead {{ display: table-header-group; }}
      .card {{ box-shadow: none; }}
      .risk-bar {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    }}
  </style>
</head>
<body>
<nav class="doc-nav">
  <span class="nav-label">Jump to</span>
  <a href="#summary">Summary</a>
  <a href="#priority-actions">Priority actions</a>
  <a href="#owner-impact">Owner impact</a>
  <a href="#categories">Categories</a>
  <a href="#detailed-changes">All changes</a>
</nav>
<main>
  <header>
    <div class="header-eyebrow">STIGPilot Change Brief</div>
    <h1 class="header-title">{escape(stig_name)} — {escape(old_doc.version or 'old')} → {escape(new_doc.version or 'new')}</h1>
    <div class="header-meta">Generated locally · {len(old_doc.controls) + len(new_doc.controls)} controls reviewed · {priority_count} priority actions</div>
    <div class="risk-bar" data-risk="{doc_risk}"></div>
  </header>
  <section id="summary" class="card summary">{escape(executive_summary(changes, config))}</section>
  <section class="grid">
    {_metric_cards(metric_rows)}
  </section>
  <h2 id="priority-actions">Priority Actions</h2>
  {priority_items}
  <h2 id="owner-impact">Owner Impact</h2>
  {_html_table(["Owner", "Changes", "High Priority", "Implementation Likely", "Evidence Updates"], owner_rows)}
  <h2 id="categories">Change Categories</h2>
  {_html_table(["Impact", "Count", "Meaning"], category_rows)}
  <h2>Top Changed Controls</h2>
  {_html_table(["Impact", "Severity", "Vuln ID", "Rule ID", "Title", "Owner", "Why it matters"], top_rows)}
  <h2 id="detailed-changes">Detailed Changes</h2>
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
            f"({impact_display(change.impact)}; {suggested_owner(control, config)})"
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
                    f"- Severity: {severity_display(control.severity or 'unspecified')}",
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


def severity_display(value: str) -> str:
    label = (value or "unspecified").upper()
    emoji = SEVERITY_EMOJI.get(value, SEVERITY_EMOJI.get(label, "⚪"))
    return f"{emoji} {label}"


def impact_display(value: str) -> str:
    label = impact_label(value)
    emoji = IMPACT_EMOJI.get(value, IMPACT_EMOJI.get(label, "⚪"))
    return f"{emoji} {label}"


def risk_level(changes: list[ControlChange]) -> str:
    impacts = Counter(change.impact for change in changes)
    if impacts.get("high_priority_review", 0):
        return "HIGH"
    if impacts.get("implementation_change_likely", 0) or impacts.get("evidence_update_likely", 0):
        return "MEDIUM"
    return "LOW"


def risk_statement(changes: list[ControlChange]) -> str:
    impacts = Counter(change.impact for change in changes)
    high = impacts.get("high_priority_review", 0)
    medium = impacts.get("implementation_change_likely", 0) + impacts.get("evidence_update_likely", 0)
    if high:
        return f"> **Risk level: HIGH** — {high} control(s) require immediate review before reusing existing tickets or evidence."
    if medium:
        return f"> **Risk level: MEDIUM** — {medium} control(s) require implementation review or evidence refresh before the next audit cycle."
    return "> **Risk level: LOW** — No high-priority changes detected. Standard review cycle applies."


def html_severity_badge(severity: str) -> str:
    return SEVERITY_BADGES.get((severity or "").lower(), f'<span class="badge badge-muted">{escape((severity or "unspecified").upper())}</span>')


def html_impact_badge(impact: str) -> str:
    return IMPACT_BADGES.get(impact, f'<span class="badge badge-muted">{escape(impact_label(impact))}</span>')


def _change_table_row(change: ControlChange, config: StigPilotConfig | None = None) -> list[str]:
    control = change.current_control or StigControl()
    return [
        html_impact_badge(change.impact),
        html_severity_badge(control.severity or "unspecified"),
        control.vuln_id or change.vuln_id,
        control.rule_id or change.rule_id,
        control.title,
        suggested_owner(control, config),
        change.reason,
    ]


def _metric_cards(rows: list[tuple[str, int]]) -> str:
    cards = []
    for label, count in rows:
        cls = "metric-zero"
        if count:
            if "High-priority" in label:
                cls = "metric-high"
            elif "Implementation" in label or "Evidence" in label or "Removed" in label or "Severity" in label:
                cls = "metric-amber"
            elif "Added" in label:
                cls = "metric-blue"
        cards.append(f'<div class="card {cls}"><div class="metric">{count}</div><div class="metric-label">{escape(label)}</div></div>')
    return "\n".join(cards)


def _html_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        column_count = len(headers)
        rows = [["No matching records."] + [""] * (column_count - 1)]
    header_html = "".join(f"<th>{escape(header)}</th>" for header in headers)
    row_html = "\n".join("<tr>" + "".join(f"<td>{_html_cell(str(cell))}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{header_html}</tr></thead><tbody>{row_html}</tbody></table>"


def _html_cell(value: str) -> str:
    if value.startswith('<span class="badge '):
        return value
    return escape(value)


def _priority_card(index: int, change: ControlChange, config: StigPilotConfig | None = None) -> str:
    control = change.current_control or StigControl()
    risk_class = "high" if change.impact == "high_priority_review" else "medium" if change.impact in {"implementation_change_likely", "evidence_update_likely"} else "low"
    control_id = control.vuln_id or change.vuln_id or control.rule_id or change.rule_id or "Control"
    return f"""
<div class="priority-card priority-{risk_class}">
  <div class="priority-header">
    <span class="priority-number">{index}</span>
    <div class="priority-title-group">
      <span class="priority-vuln-id">{escape(control_id)}</span>
      <span class="priority-title">{escape(control.title or 'Untitled')}</span>
    </div>
    <div class="priority-badges">
      {html_impact_badge(change.impact)}
      <span class="badge badge-owner">{escape(suggested_owner(control, config))}</span>
    </div>
  </div>
  <div class="priority-body">{escape(change.reason)}</div>
</div>
"""
