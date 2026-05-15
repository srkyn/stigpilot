"""Transparent keyword-based ownership and tagging rules."""

from __future__ import annotations

import re

from .config import StigPilotConfig
from .models import StigControl


DEFAULT_TAG_RULES: dict[str, tuple[str, ...]] = {
    "IAM": ("account", "authentication", "authorization", "privilege", "least privilege", "user", "group"),
    "Audit Logging": ("audit", "log", "logging", "event log", "syslog", "auditd"),
    "Endpoint Security": ("endpoint", "workstation", "server", "local security policy", "security option"),
    "Password Policy": ("password", "passphrase", "credential", "lockout"),
    "Remote Access": ("ssh", "sshd", "rdp", "remote access", "vpn", "winrm"),
    "Encryption": ("encrypt", "encryption", "tls", "ssl", "certificate", "cryptographic", "fips"),
    "Network Security": ("network", "firewall", "router", "switch", "cisco", "palo alto", "port", "acl"),
    "Database": ("database", "sql", "oracle", "postgresql", "mongodb", "mysql"),
    "Linux": ("linux", "sshd", "sudo", "auditd", "pam", "/etc/", "systemctl"),
    "Windows": ("windows", "powershell", "local security policy", "event viewer", "ntfs"),
    "GPO": ("gpo", "group policy", "policy setting"),
    "Registry": ("registry", "regedit", "hkey_", "hkcu", "hklm"),
    "Defender/AV": ("defender", "antivirus", "anti-virus", "malware", "real-time protection"),
    "Cloud": ("cloud", "azure", "aws", "gcp", "entra", "iam role"),
    "Container/Kubernetes": ("container", "kubernetes", "kubelet", "docker", "pod", "namespace"),
}

DEFAULT_OWNER_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Endpoint/Windows Admin", ("windows", "registry", "gpo", "group policy", "defender", "audit policy", "local security policy")),
    ("Linux Admin", ("linux", "sshd", "sudo", "auditd", "pam", "/etc/")),
    ("Database Admin", ("database", "sql", "oracle", "postgresql", "mongodb", "mysql")),
    ("Network/Security Engineering", ("network", "router", "firewall", "switch", "cisco", "palo alto", "acl", "vpn")),
    ("Cloud/IAM Admin", ("cloud", "azure", "aws", "gcp", "entra", "iam role")),
    ("Platform/Container Admin", ("container", "kubernetes", "kubelet", "docker")),
)

CONFIG_TERMS = (
    "configure",
    "set ",
    "enable",
    "disable",
    "registry",
    "gpo",
    "group policy",
    "/etc/",
    "sshd_config",
    "auditd",
    "firewall",
    "password",
    "encrypt",
    "certificate",
    "defender",
)


def control_text(control: StigControl | None) -> str:
    if control is None:
        return ""
    return " ".join(
        [
            control.title,
            control.stig_id,
            control.severity,
            control.check_text,
            control.fix_text,
            " ".join(control.cci_refs),
            " ".join(control.references),
        ]
    ).lower()


def tags_for_control(control: StigControl | None, config: StigPilotConfig | None = None) -> list[str]:
    """Assign explainable tags based on control text."""

    haystack = control_text(control)
    tags = [tag for tag, terms in _tag_rules(config).items() if _contains_any(haystack, terms)]
    return tags or ["General Review"]


def suggested_owner(control: StigControl | None, config: StigPilotConfig | None = None) -> str:
    """Suggest a likely owner based on transparent keyword rules."""

    haystack = control_text(control)
    for owner, terms in _owner_rules(config):
        if _contains_any(haystack, terms):
            return owner
    return "Security/GRC Analyst"


def has_config_terms(value: str) -> bool:
    return _contains_any(value.lower(), CONFIG_TERMS)


def _contains_any(value: str, terms: tuple[str, ...]) -> bool:
    return any(re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", value) for term in terms)


def _tag_rules(config: StigPilotConfig | None) -> dict[str, tuple[str, ...]]:
    rules = dict(DEFAULT_TAG_RULES)
    if not config:
        return rules
    for tag, terms in config.tag_rules.items():
        rules[tag] = rules.get(tag, ()) + terms
    return rules


def _owner_rules(config: StigPilotConfig | None) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if not config:
        return DEFAULT_OWNER_RULES
    return config.owner_rules + DEFAULT_OWNER_RULES
