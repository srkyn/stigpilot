"""Resilient XCCDF/XML parser for DISA STIG-style documents."""

from __future__ import annotations

from pathlib import Path
import re
from xml.etree import ElementTree as ET

from .models import StigControl, StigDocument
from .taxonomy import tags_for_control
from .utils import clean_text, norm_list


class StigParseError(ValueError):
    """Raised when a STIG input cannot be parsed as XML."""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _children(element: ET.Element, local_name: str | None = None) -> list[ET.Element]:
    children = list(element)
    if local_name is None:
        return children
    return [child for child in children if _local_name(child.tag) == local_name]


def _first_child(element: ET.Element, local_name: str) -> ET.Element | None:
    for child in element:
        if _local_name(child.tag) == local_name:
            return child
    return None


def _first_text(element: ET.Element, local_name: str) -> str:
    child = _first_child(element, local_name)
    if child is None:
        return ""
    return clean_text("".join(child.itertext()))


def _all_text(element: ET.Element) -> str:
    return clean_text(" ".join(element.itertext()))


def _descendants(element: ET.Element, local_name: str) -> list[ET.Element]:
    return [node for node in element.iter() if _local_name(node.tag) == local_name]


def _parse_xml(path: str | Path) -> ET.Element:
    try:
        return ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise StigParseError(f"Invalid XML in {path}: {exc}") from exc
    except OSError as exc:
        raise StigParseError(f"Unable to read {path}: {exc}") from exc


def _find_benchmark(root: ET.Element) -> ET.Element:
    if _local_name(root.tag) == "Benchmark":
        return root
    for node in root.iter():
        if _local_name(node.tag) == "Benchmark":
            return node
    return root


def _document_version(benchmark: ET.Element) -> str:
    version = _first_text(benchmark, "version")
    if version:
        return version
    plain_attr = benchmark.attrib.get("version", "")
    return clean_text(plain_attr)


def _document_release(benchmark: ET.Element) -> str:
    for status in _children(benchmark, "status"):
        text = clean_text("".join(status.itertext()))
        date = clean_text(status.attrib.get("date", ""))
        if text and date:
            return f"{text} ({date})"
        if text or date:
            return text or date
    return clean_text(benchmark.attrib.get("resolved", ""))


def _extract_vuln_id(group: ET.Element, rule: ET.Element) -> str:
    group_id = clean_text(group.attrib.get("id", ""))
    if group_id.upper().startswith("V-"):
        return group_id
    for source in (_first_text(group, "title"), _all_text(group), _all_text(rule)):
        match = re.search(r"\bV-\d+\b", source, re.IGNORECASE)
        if match:
            return match.group(0).upper()
    for ident in _descendants(rule, "ident"):
        text = clean_text("".join(ident.itertext()))
        if text.upper().startswith("V-"):
            return text
    return ""


def _extract_stig_id(rule: ET.Element) -> str:
    version = _first_text(rule, "version")
    if version:
        return version
    for ident in _descendants(rule, "ident"):
        system = clean_text(ident.attrib.get("system", "")).lower()
        text = clean_text("".join(ident.itertext()))
        if "stigid" in system or "stig" in system:
            return text
        if text and not text.upper().startswith(("CCI-", "V-")):
            return text
    return ""


def _extract_cci_refs(rule: ET.Element) -> list[str]:
    refs: list[str] = []
    for ident in _descendants(rule, "ident"):
        text = clean_text("".join(ident.itertext()))
        if text.upper().startswith("CCI-"):
            refs.append(text)
    return norm_list(refs)


def _extract_references(rule: ET.Element) -> list[str]:
    refs: list[str] = []
    for reference in _descendants(rule, "reference"):
        parts: list[str] = []
        href = clean_text(reference.attrib.get("href", ""))
        if href:
            parts.append(href)
        for child in reference:
            text = clean_text("".join(child.itertext()))
            if text:
                parts.append(text)
        own_text = clean_text(reference.text)
        if own_text:
            parts.append(own_text)
        if parts:
            refs.append(" | ".join(parts))
    return norm_list(refs)


def _extract_description_references(rule: ET.Element) -> list[str]:
    refs: list[str] = []
    description = _first_text(rule, "description")
    if not description:
        return refs
    for label in ("VulnDiscussion", "FalsePositives", "FalseNegatives", "Documentable", "Mitigations", "SeverityOverrideGuidance"):
        match = re.search(rf"<{label}>(.*?)</{label}>", description, re.IGNORECASE)
        if match:
            refs.append(f"{label}: {clean_text(match.group(1))}")
    return refs


def _extract_check_text(rule: ET.Element) -> str:
    for check in _descendants(rule, "check"):
        content = _first_text(check, "check-content")
        if content:
            return content
        text = clean_text("".join(check.itertext()))
        if text:
            return text
    return ""


def _extract_fix_text(rule: ET.Element) -> str:
    fixtext = _first_child(rule, "fixtext")
    if fixtext is not None:
        return clean_text("".join(fixtext.itertext()))
    for node in _descendants(rule, "fixtext"):
        text = clean_text("".join(node.itertext()))
        if text:
            return text
    return ""


def _raw_id(group: ET.Element, rule: ET.Element) -> str:
    candidates = [
        clean_text(rule.attrib.get("id", "")),
        clean_text(rule.attrib.get("idref", "")),
        clean_text(group.attrib.get("id", "")),
        _first_text(rule, "version"),
        _first_text(rule, "title"),
    ]
    return next((candidate for candidate in candidates if candidate), "")


def _iter_group_rules(benchmark: ET.Element) -> list[tuple[ET.Element, ET.Element]]:
    pairs: list[tuple[ET.Element, ET.Element]] = []
    for group in _descendants(benchmark, "Group"):
        for rule in _children(group, "Rule"):
            pairs.append((group, rule))
    if pairs:
        return pairs
    return [(benchmark, rule) for rule in _descendants(benchmark, "Rule")]


def parse_stig(path: str | Path) -> StigDocument:
    """Parse a STIG XCCDF/XML file into a normalized document model."""

    root = _parse_xml(path)
    benchmark = _find_benchmark(root)
    controls: list[StigControl] = []

    for group, rule in _iter_group_rules(benchmark):
        group_id = clean_text(group.attrib.get("id", ""))
        rule_id = clean_text(rule.attrib.get("id", ""))
        control = StigControl(
            vuln_id=_extract_vuln_id(group, rule),
            rule_id=rule_id,
            group_id=group_id,
            stig_id=_extract_stig_id(rule),
            title=_first_text(rule, "title") or _first_text(group, "title"),
            severity=clean_text(rule.attrib.get("severity", "")),
            check_text=_extract_check_text(rule),
            fix_text=_extract_fix_text(rule),
            cci_refs=_extract_cci_refs(rule),
            references=norm_list(_extract_references(rule) + _extract_description_references(rule)),
            raw_id=_raw_id(group, rule),
        )
        control.tags = tags_for_control(control)
        controls.append(control)

    return StigDocument(
        title=_first_text(benchmark, "title"),
        version=_document_version(benchmark),
        release=_document_release(benchmark),
        source_file=str(path),
        controls=controls,
    )
