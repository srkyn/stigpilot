"""Transparent rule-based impact classification."""

from __future__ import annotations

from difflib import SequenceMatcher

from .models import ControlChange, StigControl
from .taxonomy import has_config_terms
from .utils import clean_text

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
MEANINGFUL_TEXT_THRESHOLD = 0.86


def classify_change(change: ControlChange) -> tuple[str, str]:
    """Classify a control change and return an impact plus human-readable reason."""

    control = change.new_control or change.old_control or StigControl()
    severity = (control.severity or "").lower()
    fields = set(change.changed_fields)

    if change.change_type == "added" and severity == "high":
        return "high_priority_review", "A new high-severity control was added, so it should be triaged before lower-risk backlog work."
    if "severity" in fields and _severity_increased_to_high(change):
        if "fix_text" in fields:
            return "high_priority_review", "The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review."
        if "check_text" in fields:
            return "high_priority_review", "The severity increased to high and the check procedure changed, so validation evidence may need to be refreshed quickly."
        return "high_priority_review", "The severity increased to high, so this should be prioritized for analyst and owner review."
    if "severity" in fields and _severity_increased(change):
        return "review_recommended", "The severity increased, so ticket priority and owner review expectations may need to change."
    if "fix_text" in fields:
        if _meaningful_text_change(change.old_control, change.new_control, "fix_text"):
            return "implementation_change_likely", "The remediation text changed enough that implementation steps should be reviewed before reusing old tickets or evidence."
        return "review_recommended", "The remediation wording changed, but it appears similar enough that a quick review is likely sufficient."
    if "check_text" in fields:
        if _meaningful_text_change(change.old_control, change.new_control, "check_text"):
            return "evidence_update_likely", "The check procedure changed enough that evidence requests or validation steps may need to be refreshed."
        return "no_action_likely", "The check wording changed only slightly, so no action is likely beyond reviewer awareness."
    if change.change_type == "removed":
        return "review_recommended", "The control was removed, so downstream tickets, evidence requests, or mappings may need cleanup."
    if fields and fields <= {"title"}:
        return "no_action_likely", "Only metadata or title wording changed; no technical action is likely."
    if fields & {"cci_refs", "references"}:
        return "review_recommended", "Control mappings or references changed, which may affect traceability or evidence mapping."
    if change.change_type == "added":
        if has_config_terms(" ".join([control.title, control.check_text, control.fix_text])):
            return "implementation_change_likely", "A new control includes configuration language, so an implementation owner should review it."
        return "review_recommended", "A new control was added and should be triaged for owner, ticket, and evidence impact."
    return "review_recommended", "The change should be reviewed by an analyst."


def apply_impact(change: ControlChange) -> ControlChange:
    """Mutate a change with its impact classification."""

    change.impact, change.reason = classify_change(change)
    return change


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
    if any(term in haystack for term in ("windows", "registry", "gpo", "group policy", "defender", "local security policy")):
        requests.insert(1, "GPO, registry, or Local Security Policy export")
    if any(term in haystack for term in ("linux", "sshd", "sudo", "auditd", "pam", "/etc/")):
        requests.insert(1, "Command output showing the configured value")
        requests.insert(2, "Relevant policy or configuration file excerpt")
    if any(term in haystack for term in ("database", "sql", "oracle", "postgresql", "mongodb", "mysql")):
        requests.insert(1, "Database configuration query output or parameter export")
    if any(term in haystack for term in ("network", "router", "firewall", "switch", "cisco", "palo alto")):
        requests.insert(1, "Network device configuration excerpt or management console export")
    if any(term in haystack for term in ("cloud", "azure", "aws", "gcp", "entra")):
        requests.insert(1, "Cloud policy, role, or configuration export")
    if any(term in haystack for term in ("container", "kubernetes", "docker", "kubelet")):
        requests.insert(1, "Container or Kubernetes manifest/configuration excerpt")
    return requests


def _severity_increased(change: ControlChange) -> bool:
    if not (change.old_control and change.new_control):
        return False
    old_rank = SEVERITY_RANK.get(change.old_control.severity.lower(), 0)
    new_rank = SEVERITY_RANK.get(change.new_control.severity.lower(), 0)
    return new_rank > old_rank


def _severity_increased_to_high(change: ControlChange) -> bool:
    return bool(change.new_control and change.new_control.severity.lower() == "high" and _severity_increased(change))


def _meaningful_text_change(old: StigControl | None, new: StigControl | None, field: str) -> bool:
    old_text = clean_text(getattr(old, field, "") if old else "")
    new_text = clean_text(getattr(new, field, "") if new else "")
    if not old_text or not new_text:
        return old_text != new_text
    similarity = SequenceMatcher(None, old_text.lower(), new_text.lower()).ratio()
    if similarity < MEANINGFUL_TEXT_THRESHOLD:
        return True
    return has_config_terms(old_text) != has_config_terms(new_text)
