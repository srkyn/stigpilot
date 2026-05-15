from pathlib import Path

from stigpilot.diff import compare_documents
from stigpilot.models import StigControl, StigDocument
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


def test_compare_documents_falls_back_to_stig_id_when_rule_revision_changes():
    old = StigDocument(controls=[StigControl(rule_id="SV-1r1_rule", stig_id="APP-1", title="Old")])
    new = StigDocument(controls=[StigControl(rule_id="SV-1r2_rule", stig_id="APP-1", title="New")])

    changes = compare_documents(old, new)

    assert len(changes) == 1
    assert changes[0].change_type == "modified"
    assert changes[0].changed_fields == ["title"]


def test_compare_documents_preserves_duplicate_fallback_keys():
    old = StigDocument(
        controls=[
            StigControl(rule_id="SV-1r1_rule", title="First old"),
            StigControl(rule_id="SV-1r1_rule", title="Second old"),
        ]
    )
    new = StigDocument(
        controls=[
            StigControl(rule_id="SV-1r1_rule", title="First new"),
            StigControl(rule_id="SV-1r1_rule", title="Second new"),
        ]
    )

    changes = compare_documents(old, new)

    assert len(changes) == 2
    assert [change.new_control.title for change in changes] == ["First new", "Second new"]
