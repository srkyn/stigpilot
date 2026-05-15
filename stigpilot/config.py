"""Local configuration loading for team-specific STIGPilot rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import tomllib


@dataclass(frozen=True, slots=True)
class StigPilotConfig:
    """Optional local rules that extend built-in owner and tag mappings."""

    owner_rules: tuple[tuple[str, tuple[str, ...]], ...] = ()
    tag_rules: dict[str, tuple[str, ...]] = field(default_factory=dict)


CONFIG_EXAMPLE = """# STIGPilot local team routing config.
#
# Custom owner rules are checked before built-in defaults.
# Custom tag rules are merged with built-in tags.

[[owner_rules]]
owner = "Windows Platform Team"
keywords = ["windows audit policy", "local security policy", "defender baseline", "gpresult"]

[[owner_rules]]
owner = "Identity/IAM Team"
keywords = ["privileged account", "authentication", "account lifecycle", "password lockout"]

[[owner_rules]]
owner = "Network Security Team"
keywords = ["firewall management", "router", "switch", "palo alto", "cisco"]

[tag_rules]
"Privileged Access" = ["privileged account", "domain admin", "sudoers"]
"Evidence Refresh" = ["export applied", "validation artifact", "evidence package"]
"Policy Exception Review" = ["waiver", "exception", "documentable"]
"""


def load_config(path: str | Path | None) -> StigPilotConfig | None:
    """Load an optional TOML config file.

    The config deliberately extends the built-in rules instead of replacing
    them, so a thin team customization file cannot accidentally erase useful
    default behavior.
    """

    if path is None:
        return None

    config_path = Path(path)
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML config in {config_path}: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"Unable to read config {config_path}: {exc}") from exc

    return StigPilotConfig(
        owner_rules=_parse_owner_rules(data.get("owner_rules", [])),
        tag_rules=_parse_tag_rules(data.get("tag_rules", {})),
    )


def _parse_owner_rules(value: Any) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, list):
        raise ValueError("Config field 'owner_rules' must be a TOML array of tables.")

    parsed: list[tuple[str, tuple[str, ...]]] = []
    for idx, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"owner_rules entry {idx} must be a table.")
        owner = item.get("owner")
        keywords = item.get("keywords")
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError(f"owner_rules entry {idx} requires a non-empty owner string.")
        parsed.append((owner.strip(), _parse_keywords(keywords, f"owner_rules entry {idx} keywords")))
    return tuple(parsed)


def _parse_tag_rules(value: Any) -> dict[str, tuple[str, ...]]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise ValueError("Config field 'tag_rules' must be a TOML table.")

    parsed: dict[str, tuple[str, ...]] = {}
    for tag, keywords in value.items():
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError("tag_rules keys must be non-empty strings.")
        parsed[tag.strip()] = _parse_keywords(keywords, f"tag_rules.{tag}")
    return parsed


def _parse_keywords(value: Any, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        keyword_values = [value]
    elif isinstance(value, list):
        keyword_values = value
    else:
        raise ValueError(f"Config field '{field_name}' must be a string or array of strings.")

    keywords: list[str] = []
    for keyword in keyword_values:
        if not isinstance(keyword, str) or not keyword.strip():
            raise ValueError(f"Config field '{field_name}' contains an invalid keyword.")
        keywords.append(keyword.strip().lower())
    return tuple(keywords)
