"""Shared utility helpers."""

from __future__ import annotations

import re
from pathlib import Path


def clean_text(value: str | None) -> str:
    """Collapse XML text into a readable single-space string."""

    if not value:
        return ""
    return re.sub(r"\s+", " ", value).strip()


def summarize(value: str, limit: int = 220) -> str:
    """Return a concise, CSV-friendly summary."""

    text = clean_text(value)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def ensure_parent(path: str | Path) -> None:
    """Create the parent directory for an output file when needed."""

    Path(path).parent.mkdir(parents=True, exist_ok=True)


def norm_list(values: list[str]) -> list[str]:
    """Normalize, deduplicate, and sort a string list."""

    seen: set[str] = set()
    normalized: list[str] = []
    for value in values:
        item = clean_text(value)
        if item and item not in seen:
            seen.add(item)
            normalized.append(item)
    return sorted(normalized)
