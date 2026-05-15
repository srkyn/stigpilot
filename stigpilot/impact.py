"""Transparent rule-based impact classification."""

from __future__ import annotations

import re

from .models import ControlChange, StigControl


WINDOWS_TERMS = ("windows", "registry", "gpo", "defender", "audit policy", "local security policy")
LINUX_TERMS = ("linux", "sshd", "sudo", "auditd", "pam")
DB_TERMS = ("database", "sql", "oracle", "postgresql", "mongodb")
NETWORK_TERMS = ("network", "router", "firewall", "switch", "cisco", "palo alto")


def classify_change(change: ControlChange) -> tuple[str, str]:
    """Classify a control change and return an impact plus human-readable reason."""

    control = change.new_control or change.old_control or StigControl()
    severity = (control.severity or "").lower()
    fields = set(change.changed_fields)

    if (change.change_type == "added" and severity == "high") or (
        "severity" in fields and change.new_control and change.new_control.severity.lower() == "high"
    ):
        return "high_priority_review", "The control is new or now rated high severity."
    if "fix_text" in fields:
        return "implementation_change_likely", "Fix guidance changed, so implementation steps may need updates."
    if "check_text" in fields:
        return "evidence_update_likely", "Check guidance changed, so validation evidence may need to change."
    if change.change_type == "removed":
        return "review_recommended", "The control was removed and downstream tickets or evidence mappings may need cleanup."
    if fields and fields <= {"title"}:
        return "no_action_likely", "Only the title changed; no technical action is likely."
    if fields & {"cci_refs", "references"}:
        return "review_recommended", "Control mappings or references changed and should be reviewed."
    if change.change_type == "added":
        return "review_recommended", "A new control was added and should be triaged."
    return "review_recommended", "The change should be reviewed by an analyst."


def apply_impact(change: ControlChange) -> ControlChange:
    """Mutate a change with its impact classification."""

    change.impact, change.reason = classify_change(change)
    return change


def suggested_owner(control: StigControl | None) -> str:
    """Suggest a likely owner based on control language."""

    if control is None:
        return "Security/GRC Analyst"
    haystack = " ".join([control.title, control.check_text, control.fix_text]).lower()
    if _contains_any(haystack, WINDOWS_TERMS):
        return "Endpoint/Windows Admin"
    if _contains_any(haystack, LINUX_TERMS):
        return "Linux Admin"
    if _contains_any(haystack, DB_TERMS):
        return "Database Admin"
    if _contains_any(haystack, NETWORK_TERMS):
        return "Network/Security Engineering"
    return "Security/GRC Analyst"


def evidence_requests(control: StigControl | None) -> list[str]:
    """Generate practical evidence requests for a control."""

    requests = [
        "Screenshot or export of the relevant setting",
        "Date/time of validation",
        "System or asset name",
        "Reviewer notes",
    ]
    if control is None:
        return requests

    haystack = " ".join([control.title, control.check_text, control.fix_text]).lower()
    if _contains_any(haystack, WINDOWS_TERMS):
        requests.insert(1, "GPO, registry, or Local Security Policy export")
    if _contains_any(haystack, LINUX_TERMS):
        requests.insert(1, "Command output showing the configured value")
        requests.insert(2, "Relevant policy or configuration file excerpt")
    if _contains_any(haystack, DB_TERMS):
        requests.insert(1, "Database configuration query output or parameter export")
    if _contains_any(haystack, NETWORK_TERMS):
        requests.insert(1, "Network device configuration excerpt or management console export")
    return requests


def _contains_any(value: str, terms: tuple[str, ...]) -> bool:
    return any(re.search(rf"\b{re.escape(term)}\b", value) for term in terms)
