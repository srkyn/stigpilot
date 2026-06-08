from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).parents[1]
DOC_ROOTS = [ROOT / "README.md", ROOT / "docs", ROOT / "examples"]
LINK_PATTERN = re.compile(r"!?\[[^\]]+\]\(([^)]+)\)")


def _markdown_files() -> list[Path]:
    files = [ROOT / "README.md"]
    for root in (ROOT / "docs", ROOT / "examples"):
        files.extend(path for path in root.rglob("*.md") if path.is_file())
    return files


def _local_target(markdown_file: Path, raw_target: str) -> Path | None:
    target = raw_target.strip()
    if not target or target.startswith(("#", "http://", "https://", "mailto:")):
        return None
    target = target.split("#", 1)[0].strip()
    if not target:
        return None
    target = unquote(target).strip("<>")
    return (markdown_file.parent / target).resolve()


def test_local_markdown_links_point_to_existing_files():
    broken_links: list[str] = []

    for markdown_file in _markdown_files():
        text = markdown_file.read_text(encoding="utf-8-sig")
        for match in LINK_PATTERN.finditer(text):
            target = _local_target(markdown_file, match.group(1))
            if target is None:
                continue
            if not target.exists():
                broken_links.append(
                    f"{markdown_file.relative_to(ROOT)} links to missing file {match.group(1)}"
                )

    assert broken_links == []
