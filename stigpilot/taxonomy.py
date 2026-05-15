"""Transparent keyword-based ownership and tagging rules."""

from __future__ import annotations

import re

from .config import StigPilotConfig
from .models import StigControl


DEFAULT_TAG_RULES: dict[str, tuple[str, ...]] = {
    "IAM": ("account", "authentication", "authorization", "privilege", "privileged access", "least privilege", "user", "group", "role", "identity"),
    "Audit Logging": ("audit", "audit policy", "log", "logging", "event log", "event forwarding", "syslog", "auditd", "siem"),
    "Endpoint Security": ("endpoint", "workstation", "server", "local security policy", "security option", "baseline"),
    "Password Policy": ("password", "passphrase", "credential", "lockout", "complexity", "expiration"),
    "Remote Access": ("ssh", "sshd", "rdp", "remote access", "vpn", "winrm", "banner"),
    "Encryption": ("encrypt", "encryption", "tls", "ssl", "certificate", "cryptographic", "fips", "cipher"),
    "Network Security": ("network", "firewall", "router", "switch", "cisco", "palo alto", "port", "acl", "management access"),
    "Database": ("database", "sql", "oracle", "postgresql", "mongodb", "mysql", "dbms", "stored procedure"),
    "Linux": ("linux", "sshd", "sudo", "sudoers", "auditd", "pam", "/etc/", "systemctl", "journald"),
    "Windows": ("windows", "powershell", "local security policy", "event viewer", "ntfs", "secedit", "windows defender"),
    "GPO": ("gpo", "group policy", "policy setting", "gpresult", "lgpo"),
    "Registry": ("registry", "regedit", "hkey_", "hkcu", "hklm", "reg add"),
    "Defender/AV": ("defender", "windows defender", "antivirus", "anti-virus", "malware", "real-time protection", "tamper protection"),
    "Cloud": ("cloud", "azure", "aws", "gcp", "entra", "iam role", "security group", "conditional access"),
    "Container/Kubernetes": ("container", "kubernetes", "kubelet", "docker", "pod", "namespace", "kubectl", "helm"),
    "Browser Security": ("chrome", "browser", "safe browsing", "extension", "password manager", "remote debugging", "enterprise policy"),
}

DEFAULT_OWNER_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Endpoint/Windows Admin", ("windows", "registry", "gpo", "group policy", "defender", "audit policy", "local security policy", "secedit", "gpresult")),
    ("Linux Admin", ("linux", "sshd", "sudo", "sudoers", "auditd", "pam", "/etc/", "systemctl")),
    ("IAM/Security Admin", ("authentication", "authorization", "privileged access", "least privilege", "account lifecycle", "lockout")),
    ("Database Admin", ("database", "sql", "oracle", "postgresql", "mongodb", "mysql", "dbms")),
    ("Network/Security Engineering", ("network", "router", "firewall", "switch", "cisco", "palo alto", "acl", "vpn", "management access")),
    ("Cloud/IAM Admin", ("cloud", "azure", "aws", "gcp", "entra", "iam role", "conditional access")),
    ("Platform/Container Admin", ("container", "kubernetes", "kubelet", "docker", "kubectl")),
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
