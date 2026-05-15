from pathlib import Path

from stigpilot.diff import compare_documents
from stigpilot.parser import parse_stig
from stigpilot.reports import change_brief, manager_summary_report


def test_manager_summary_report_is_concise_and_actionable():
    old = parse_stig(Path(__file__).parent / "fixtures_old.xml")
    new = parse_stig(Path(__file__).parent / "fixtures_new.xml")
    changes = compare_documents(old, new)

    report = manager_summary_report(old, new, changes)

    assert "# STIGPilot Manager Summary" in report
    assert "## Executive Readout" in report
    assert "## Owner Impact" in report
    assert "## Top Actions" in report
    assert "## Assumptions and Limitations" in report
    assert "High-priority review" in report
    assert "Use the remediation backlog CSV" in report


def test_change_brief_uses_readable_priority_actions_and_labels():
    old = parse_stig(Path(__file__).parent / "fixtures_old.xml")
    new = parse_stig(Path(__file__).parent / "fixtures_new.xml")
    changes = compare_documents(old, new)

    report = change_brief(old, new, changes)

    assert "## Priority Actions" in report
    assert "1. **" in report
    assert "Impact: High-priority review" in report
    assert "| High-priority review |" in report
