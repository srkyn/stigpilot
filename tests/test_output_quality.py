from pathlib import Path


ROOT = Path(__file__).parents[1]
PUBLIC_OUTPUT_ROOTS = [
    ROOT / "docs" / "sample-packet",
    ROOT / "examples" / "chrome_windows_output",
    ROOT / "examples" / "government_mode_output",
    ROOT / "examples" / "packet_output",
    ROOT / "examples" / "portfolio_output",
    ROOT / "examples" / "sample_output",
]
TEXT_SUFFIXES = {".csv", ".html", ".json", ".md", ".txt", ".xml"}
EM_DASH = chr(0x2014)
RED_CIRCLE = chr(0x1F534)
YELLOW_CIRCLE = chr(0x1F7E1)
BLUE_CIRCLE = chr(0x1F535)
WHITE_CIRCLE = chr(0x26AA)


def _public_output_files() -> list[Path]:
    files: list[Path] = []
    for root in PUBLIC_OUTPUT_ROOTS:
        files.extend(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES)
    return files


def test_public_outputs_do_not_include_local_machine_paths():
    forbidden = [
        "C:\\Users\\",
        "Documents\\CSProjects",
        "CSProjects\\stigpilot",
    ]

    offenders = []
    for path in _public_output_files():
        text = path.read_text(encoding="utf-8-sig")
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.relative_to(ROOT)} contains {needle}")

    assert offenders == []


def test_public_outputs_use_plain_professional_markers():
    forbidden = [EM_DASH, RED_CIRCLE, YELLOW_CIRCLE, BLUE_CIRCLE, WHITE_CIRCLE]

    offenders = []
    for path in _public_output_files():
        text = path.read_text(encoding="utf-8-sig")
        for marker in forbidden:
            if marker in text:
                offenders.append(f"{path.relative_to(ROOT)} contains {repr(marker)}")

    assert offenders == []


def test_committed_html_reports_are_self_contained():
    forbidden = ["fonts.googleapis.com", "fonts.gstatic.com", "rel=\"preconnect\""]

    offenders = []
    for path in _public_output_files():
        if path.suffix.lower() != ".html":
            continue
        text = path.read_text(encoding="utf-8-sig")
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.relative_to(ROOT)} contains {needle}")

    assert offenders == []
