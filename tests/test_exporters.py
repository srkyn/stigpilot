import csv
from pathlib import Path

from stigpilot.diff import compare_documents
from stigpilot.exporters import write_jira_csv, write_servicenow_csv
from stigpilot.parser import parse_stig
from stigpilot.reports import evidence_checklist


ROOT = Path(__file__).parents[1]


def _changes():
    old = parse_stig(ROOT / "examples" / "sample_input" / "old.xml")
    new = parse_stig(ROOT / "examples" / "sample_input" / "new.xml")
    return compare_documents(old, new)


def test_evidence_checklist_contains_checkboxes():
    document = parse_stig(ROOT / "examples" / "sample_input" / "new.xml")

    report = evidence_checklist(document)

    assert "- [ ] Asset/System:" in report
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
