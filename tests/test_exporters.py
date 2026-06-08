import csv
import json
from pathlib import Path

from stigpilot.diff import compare_documents
from stigpilot.exporters import github_issue_markdown, remediation_draft_markdown, write_changes_json, write_jira_csv, write_servicenow_csv
from stigpilot.parser import parse_stig
from stigpilot.reports import evidence_checklist


ROOT = Path(__file__).parents[1]
RED_CIRCLE = chr(0x1F534)
YELLOW_CIRCLE = chr(0x1F7E1)
BLUE_CIRCLE = chr(0x1F535)


def _changes():
    old = parse_stig(ROOT / "examples" / "sample_input" / "old.xml")
    new = parse_stig(ROOT / "examples" / "sample_input" / "new.xml")
    return compare_documents(old, new)


def _docs():
    old = parse_stig(ROOT / "examples" / "sample_input" / "old.xml")
    new = parse_stig(ROOT / "examples" / "sample_input" / "new.xml")
    return old, new


def test_evidence_checklist_contains_checkboxes():
    document = parse_stig(ROOT / "examples" / "sample_input" / "new.xml")

    report = evidence_checklist(document)

    assert "- [ ] Asset/System:" in report
    assert "- [ ] Environment:" in report
    assert "- [ ] Screenshot or export of the relevant setting" in report


def test_jira_csv_contains_expected_headers(tmp_path: Path):
    path = tmp_path / "jira.csv"

    write_jira_csv(_changes(), path)

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == ["Summary", "Issue Type", "Priority", "Labels", "Assignee", "Description"]


def test_servicenow_csv_contains_expected_headers(tmp_path: Path):
    path = tmp_path / "servicenow.csv"

    write_servicenow_csv(_changes(), path)

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == [
            "short_description",
            "description",
            "assignment_group",
            "priority",
            "u_stig_vuln_id",
            "u_stig_rule_id",
            "u_stig_impact",
            "u_stig_tags",
        ]


def test_changes_json_contains_summary_and_actionable_fields(tmp_path: Path):
    path = tmp_path / "changes.json"
    old, new = _docs()
    changes = compare_documents(old, new)

    write_changes_json(changes, path, old, new)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["schema"] == "docs/schemas/changes.schema.json"
    assert payload["summary"]["total"] == 4
    assert payload["source"]["old_control_count"] == 3
    assert payload["changes"][0]["impact_label"]
    assert "suggested_owner" in payload["changes"][0]
    assert "evidence_needed" in payload["changes"][0]


def test_remediation_draft_markdown_is_review_only():
    report = remediation_draft_markdown(_changes())

    assert "# STIGPilot Remediation Drafts" in report
    assert "Review-only planning notes" in report
    assert "Changes made by STIGPilot: none" in report
    assert "not an executable patch" in report
    assert "Review Before Action" in report
    assert "The control was removed from the compared release" in report
    assert "Do not remove a local control solely because it disappeared" in report
    assert RED_CIRCLE not in report
    assert YELLOW_CIRCLE not in report
    assert BLUE_CIRCLE not in report


def test_github_issue_markdown_uses_plain_text_labels():
    report = github_issue_markdown(_changes())

    assert "## Issue 1" in report
    assert "- Severity: HIGH" in report
    assert "- Impact: High-priority review" in report
    assert RED_CIRCLE not in report
    assert YELLOW_CIRCLE not in report
    assert BLUE_CIRCLE not in report
