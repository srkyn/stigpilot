"""Domain models for parsed STIG content and change analysis."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class StigControl:
    """A normalized control extracted from an XCCDF Group/Rule pair."""

    vuln_id: str = ""
    rule_id: str = ""
    group_id: str = ""
    stig_id: str = ""
    title: str = ""
    severity: str = ""
    check_text: str = ""
    fix_text: str = ""
    cci_refs: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw_id: str = ""

    @property
    def comparison_key(self) -> str:
        """Best-effort stable identifier for diffing across releases."""

        return self.vuln_id or self.rule_id or self.group_id or self.raw_id


@dataclass(slots=True)
class StigDocument:
    """A parsed STIG/XCCDF document."""

    title: str = ""
    version: str = ""
    release: str = ""
    source_file: str = ""
    controls: list[StigControl] = field(default_factory=list)


@dataclass(slots=True)
class ControlChange:
    """A change detected between two STIG documents."""

    change_type: str
    vuln_id: str = ""
    rule_id: str = ""
    old_control: StigControl | None = None
    new_control: StigControl | None = None
    changed_fields: list[str] = field(default_factory=list)
    impact: str = ""
    reason: str = ""

    @property
    def current_control(self) -> StigControl | None:
        """Return the most actionable version of the changed control."""

        return self.new_control or self.old_control
