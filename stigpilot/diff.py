"""Diff logic for comparing two parsed STIG documents."""

from __future__ import annotations

from .impact import apply_impact
from .models import ControlChange, StigControl, StigDocument
from .utils import clean_text, norm_list

DIFF_FIELDS = ("title", "severity", "check_text", "fix_text", "cci_refs", "references")


def _index_controls(controls: list[StigControl]) -> dict[str, StigControl]:
    indexed: dict[str, StigControl] = {}
    for idx, control in enumerate(controls):
        key = control.comparison_key or f"control-{idx}"
        indexed[key] = control
    return indexed


def _field_changed(old: StigControl, new: StigControl, field: str) -> bool:
    old_value = getattr(old, field)
    new_value = getattr(new, field)
    if isinstance(old_value, list) and isinstance(new_value, list):
        return norm_list(old_value) != norm_list(new_value)
    return clean_text(str(old_value)) != clean_text(str(new_value))


def compare_documents(old: StigDocument, new: StigDocument) -> list[ControlChange]:
    """Compare two STIG documents and return classified changes."""

    old_index = _index_controls(old.controls)
    new_index = _index_controls(new.controls)
    changes: list[ControlChange] = []

    for key in sorted(new_index.keys() - old_index.keys()):
        control = new_index[key]
        changes.append(
            apply_impact(
                ControlChange(
                    change_type="added",
                    vuln_id=control.vuln_id,
                    rule_id=control.rule_id,
                    new_control=control,
                )
            )
        )

    for key in sorted(old_index.keys() - new_index.keys()):
        control = old_index[key]
        changes.append(
            apply_impact(
                ControlChange(
                    change_type="removed",
                    vuln_id=control.vuln_id,
                    rule_id=control.rule_id,
                    old_control=control,
                )
            )
        )

    for key in sorted(old_index.keys() & new_index.keys()):
        old_control = old_index[key]
        new_control = new_index[key]
        changed_fields = [field for field in DIFF_FIELDS if _field_changed(old_control, new_control, field)]
        if not changed_fields:
            continue
        change_type = "severity_changed" if changed_fields == ["severity"] else "modified"
        if "severity" in changed_fields and change_type != "modified":
            change_type = "severity_changed"
        changes.append(
            apply_impact(
                ControlChange(
                    change_type=change_type,
                    vuln_id=new_control.vuln_id or old_control.vuln_id,
                    rule_id=new_control.rule_id or old_control.rule_id,
                    old_control=old_control,
                    new_control=new_control,
                    changed_fields=changed_fields,
                )
            )
        )

    return changes
