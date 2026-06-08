from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools" / "STIGPilot-Gov.ps1"


def powershell_executable() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell")


def run_gov_mode(*args: str) -> subprocess.CompletedProcess[str]:
    shell = powershell_executable()
    if shell is None:
        pytest.skip("PowerShell is not available on this runner")
    return subprocess.run(
        [
            shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            *args,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_government_mode_script_and_docs_exist():
    assert SCRIPT.exists()
    assert (ROOT / "docs" / "government-mode.md").exists()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Government Mode" in readme
    assert "STIGPilot-Gov.ps1" in readme


def test_government_mode_help_runs():
    result = run_gov_mode("-Command", "help")

    assert result.returncode == 0
    assert "STIGPilot Government Mode" in result.stdout
    assert "PowerShell-only" in result.stdout
    assert "doctor" in result.stdout


def test_government_mode_doctor_runs():
    result = run_gov_mode("-Command", "doctor")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "STIGPilot Government Mode Doctor" in result.stdout
    assert "PowerShell version" in result.stdout
    assert "Sample parse" in result.stdout
    assert "Sample diff" in result.stdout
    assert "Government Mode is ready" in result.stdout


def test_government_mode_packet_writes_core_outputs(tmp_path: Path):
    out = tmp_path / "gov"

    result = run_gov_mode(
        "-Command",
        "packet",
        "-Old",
        str(ROOT / "examples" / "sample_input" / "old.xml"),
        "-New",
        str(ROOT / "examples" / "sample_input" / "new.xml"),
        "-OutDir",
        str(out),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "STIGPilot Government Mode Diff Summary" in result.stdout
    assert "Start here" in result.stdout
    assert (out / "START_HERE.md").exists()
    assert (out / "change-brief.md").exists()
    assert (out / "remediation-backlog.csv").exists()
    assert (out / "changes.json").exists()
    assert (out / "evidence-checklist.md").exists()
    assert (out / "jira-import.csv").exists()
    assert (out / "servicenow-import.csv").exists()
    assert (out / "github-issues.md").exists()

    brief = (out / "change-brief.md").read_text(encoding="utf-8")
    checklist = (out / "evidence-checklist.md").read_text(encoding="utf-8")
    backlog = (out / "remediation-backlog.csv").read_text(encoding="utf-8-sig")
    jira = (out / "jira-import.csv").read_text(encoding="utf-8-sig")
    servicenow = (out / "servicenow-import.csv").read_text(encoding="utf-8-sig")
    issues = (out / "github-issues.md").read_text(encoding="utf-8")
    start_here = (out / "START_HERE.md").read_text(encoding="utf-8")
    changes = json.loads((out / "changes.json").read_text(encoding="utf-8-sig"))

    assert "# STIGPilot Government Mode Change Brief" in brief
    assert "## At-a-Glance" in brief
    assert "owner group(s) with the most priority work are Endpoint/Windows Admin, Network/Security Engineering, Linux Admin" in brief
    assert "- [ ]" in checklist
    assert "- [ ] Asset/System:" in checklist
    assert "- [ ] Environment:" in checklist
    assert "Suggested Owner" in backlog
    assert "Summary" in jira
    assert "Issue Type" in jira
    assert "short_description" in servicenow
    assert "assignment_group" in servicenow
    assert "# STIGPilot Government Mode GitHub Issue Drafts" in issues
    assert "### Acceptance Criteria" in issues
    assert "# STIGPilot Government Mode Packet" in start_here
    assert "Open These First" in start_here
    assert "Next 15 Minutes" in start_here
    assert changes["source"]["old_file"] == str(Path("examples") / "sample_input" / "old.xml")
    assert changes["source"]["new_file"] == str(Path("examples") / "sample_input" / "new.xml")


def test_government_mode_inspect_accepts_complete_packet(tmp_path: Path):
    out = tmp_path / "gov"
    packet = run_gov_mode(
        "-Command",
        "packet",
        "-Old",
        str(ROOT / "examples" / "sample_input" / "old.xml"),
        "-New",
        str(ROOT / "examples" / "sample_input" / "new.xml"),
        "-OutDir",
        str(out),
    )

    result = run_gov_mode("-Command", "inspect", "-OutDir", str(out))

    assert packet.returncode == 0, packet.stdout + packet.stderr
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Packet Inspection" in result.stdout
    assert "Packet is handoff-ready" in result.stdout


def test_government_mode_inspect_rejects_incomplete_packet(tmp_path: Path):
    out = tmp_path / "gov"
    out.mkdir()
    (out / "START_HERE.md").write_text("# Packet\n", encoding="utf-8")

    result = run_gov_mode("-Command", "inspect", "-OutDir", str(out))

    assert result.returncode == 1
    assert "Packet is incomplete" in result.stdout
    assert "change-brief.md" in result.stdout


def test_government_mode_archive_writes_zip_after_inspection(tmp_path: Path):
    out = tmp_path / "gov"
    archive = tmp_path / "gov.zip"
    packet = run_gov_mode(
        "-Command",
        "packet",
        "-Old",
        str(ROOT / "examples" / "sample_input" / "old.xml"),
        "-New",
        str(ROOT / "examples" / "sample_input" / "new.xml"),
        "-OutDir",
        str(out),
    )

    result = run_gov_mode("-Command", "archive", "-OutDir", str(out), "-Zip", str(archive))

    assert packet.returncode == 0, packet.stdout + packet.stderr
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Wrote packet archive" in result.stdout
    assert archive.exists()
    with zipfile.ZipFile(archive) as zip_file:
        names = set(zip_file.namelist())
    assert "START_HERE.md" in names
    assert "change-brief.md" in names
    assert "remediation-backlog.csv" in names


def test_government_mode_archive_rejects_existing_zip_without_force(tmp_path: Path):
    out = tmp_path / "gov"
    archive = tmp_path / "gov.zip"
    packet = run_gov_mode(
        "-Command",
        "packet",
        "-Old",
        str(ROOT / "examples" / "sample_input" / "old.xml"),
        "-New",
        str(ROOT / "examples" / "sample_input" / "new.xml"),
        "-OutDir",
        str(out),
    )
    archive.write_text("already here", encoding="utf-8")

    result = run_gov_mode("-Command", "archive", "-OutDir", str(out), "-Zip", str(archive))

    assert packet.returncode == 0, packet.stdout + packet.stderr
    assert result.returncode == 1
    assert "Archive already exists" in result.stdout


def test_government_mode_archive_rejects_incomplete_packet(tmp_path: Path):
    out = tmp_path / "gov"
    out.mkdir()
    (out / "START_HERE.md").write_text("# Packet\n", encoding="utf-8")

    result = run_gov_mode("-Command", "archive", "-OutDir", str(out), "-Zip", str(tmp_path / "gov.zip"))

    assert result.returncode == 1
    assert "Archive skipped because packet is incomplete" in result.stdout


def test_government_mode_parse_writes_csv_and_json(tmp_path: Path):
    csv_out = tmp_path / "controls.csv"
    json_out = tmp_path / "controls.json"

    result = run_gov_mode(
        "-Command",
        "parse",
        "-Input",
        str(ROOT / "examples" / "sample_input" / "new.xml"),
        "-Csv",
        str(csv_out),
        "-Json",
        str(json_out),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert csv_out.exists()
    assert json_out.exists()
    assert "Vuln ID" in csv_out.read_text(encoding="utf-8-sig")
    document = json.loads(json_out.read_text(encoding="utf-8-sig"))
    assert document["source_file"] == str(Path("examples") / "sample_input" / "new.xml")


def test_government_mode_packet_can_filter_by_impact_and_owner(tmp_path: Path):
    out = tmp_path / "gov-windows"

    result = run_gov_mode(
        "-Command",
        "packet",
        "-Old",
        str(ROOT / "examples" / "sample_input" / "old.xml"),
        "-New",
        str(ROOT / "examples" / "sample_input" / "new.xml"),
        "-OutDir",
        str(out),
        "-Impact",
        "high_priority_review",
        "-Owner",
        "Endpoint/Windows Admin",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Unfiltered changes" in result.stdout
    assert "Impact filter" in result.stdout
    assert "Owner filter" in result.stdout

    brief = (out / "change-brief.md").read_text(encoding="utf-8")
    backlog = (out / "remediation-backlog.csv").read_text(encoding="utf-8-sig")
    issues = (out / "github-issues.md").read_text(encoding="utf-8")

    assert "Windows audit policy" in brief
    assert "Firewall management access" not in brief
    assert "Endpoint/Windows Admin" in backlog
    assert "Network/Security Engineering" not in backlog
    assert "Windows audit policy" in issues


def test_government_mode_rejects_unknown_impact_filter(tmp_path: Path):
    result = run_gov_mode(
        "-Command",
        "packet",
        "-Old",
        str(ROOT / "examples" / "sample_input" / "old.xml"),
        "-New",
        str(ROOT / "examples" / "sample_input" / "new.xml"),
        "-OutDir",
        str(tmp_path / "bad-impact"),
        "-Impact",
        "urgent_magic",
    )

    assert result.returncode == 1
    assert "-Impact must be one of" in result.stdout
