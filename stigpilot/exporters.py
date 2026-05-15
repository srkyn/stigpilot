"""CSV and JSON export helpers."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .impact import evidence_requests, suggested_owner
from .models import ControlChange, StigControl, StigDocument
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
                    "ticket_summary": f"Review STIG control {control.vuln_id or control.rule_id}: {control.title}",
                    "description": summarize(f"Check: {control.check_text} Fix: {control.fix_text}", 500),
                    "evidence_needed": "; ".join(evidence_requests(control)),
                    "status": "Not Started",
                    "notes": "",
                }
            )
