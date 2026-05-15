from pathlib import Path

from stigpilot.diff import compare_documents
from stigpilot.parser import parse_stig


def test_compare_documents_detects_added_removed_and_modified():
    old = parse_stig(Path(__file__).parent / "fixtures_old.xml")
    new = parse_stig(Path(__file__).parent / "fixtures_new.xml")

    changes = compare_documents(old, new)
    by_vuln = {change.vuln_id: change for change in changes}

    assert by_vuln["V-100004"].change_type == "added"
    assert by_vuln["V-100003"].change_type == "removed"
    assert by_vuln["V-100001"].change_type == "modified"
    assert "severity" in by_vuln["V-100001"].changed_fields
    assert "fix_text" in by_vuln["V-100001"].changed_fields
    assert by_vuln["V-100002"].impact == "evidence_update_likely"
