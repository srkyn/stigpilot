from stigpilot.impact import classify_change, evidence_requests
from stigpilot.models import ControlChange, StigControl
from stigpilot.taxonomy import suggested_owner


def test_high_added_control_is_high_priority():
    control = StigControl(vuln_id="V-1", severity="high", title="Firewall setting")
    impact, reason = classify_change(ControlChange(change_type="added", new_control=control))

    assert impact == "high_priority_review"
    assert "high-severity" in reason


def test_fix_text_change_is_implementation_change():
    change = ControlChange(
        change_type="modified",
        old_control=StigControl(fix_text="old"),
        new_control=StigControl(fix_text="new"),
        changed_fields=["fix_text"],
    )

    assert classify_change(change)[0] == "implementation_change_likely"


def test_owner_and_evidence_are_rule_based():
    control = StigControl(
        title="Linux sshd must be configured",
        check_text="Run sshd -T and inspect /etc/ssh/sshd_config.",
    )

    assert suggested_owner(control) == "Linux Admin"
    assert any("Command output" in item for item in evidence_requests(control))


def test_minor_check_wording_change_is_no_action_likely():
    change = ControlChange(
        change_type="modified",
        old_control=StigControl(check_text="Review the configured audit policy setting."),
        new_control=StigControl(check_text="Review the configured audit policy setting carefully."),
        changed_fields=["check_text"],
    )

    assert classify_change(change)[0] == "no_action_likely"
