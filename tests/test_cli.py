from pathlib import Path
import shutil

from typer.testing import CliRunner

from stigpilot.cli import app


runner = CliRunner()
ROOT = Path(__file__).parents[1]


def test_cli_demo_writes_reports(tmp_path: Path):
    out = tmp_path / "demo"

    result = runner.invoke(app, ["demo", "--out", str(out)])

    assert result.exit_code == 0
    assert "Start here" in result.output
    assert (out / "change-brief.md").exists()
    assert (out / "manager-summary.md").exists()
    assert (out / "remediation-backlog.csv").exists()


def test_cli_parse_writes_csv_and_json(tmp_path: Path):
    csv_out = tmp_path / "controls.csv"
    json_out = tmp_path / "controls.json"

    result = runner.invoke(
        app,
        ["parse", str(ROOT / "examples" / "sample_input" / "new.xml"), "--csv", str(csv_out), "--json", str(json_out)],
    )

    assert result.exit_code == 0
    assert csv_out.exists()
    assert json_out.exists()


def test_cli_diff_writes_markdown_and_csv(tmp_path: Path):
    report = tmp_path / "change-brief.md"
    backlog = tmp_path / "backlog.csv"

    result = runner.invoke(
        app,
        [
            "diff",
            str(ROOT / "examples" / "sample_input" / "old.xml"),
            str(ROOT / "examples" / "sample_input" / "new.xml"),
            "--out",
            str(report),
            "--csv",
            str(backlog),
        ],
    )

    assert result.exit_code == 0
    assert "STIGPilot Diff Summary" in result.output
    assert report.exists()
    assert backlog.exists()


def test_cli_diff_can_filter_by_impact_and_owner(tmp_path: Path):
    report = tmp_path / "endpoint-high.md"
    backlog = tmp_path / "endpoint-high.csv"

    result = runner.invoke(
        app,
        [
            "diff",
            str(ROOT / "examples" / "sample_input" / "old.xml"),
            str(ROOT / "examples" / "sample_input" / "new.xml"),
            "--out",
            str(report),
            "--csv",
            str(backlog),
            "--impact",
            "high_priority_review",
            "--owner",
            "Endpoint/Windows Admin",
        ],
    )

    assert result.exit_code == 0
    text = report.read_text(encoding="utf-8")
    assert "Windows audit policy" in text
    assert "Firewall management access" not in text


def test_cli_diff_rejects_unknown_impact_filter(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "diff",
            str(ROOT / "examples" / "sample_input" / "old.xml"),
            str(ROOT / "examples" / "sample_input" / "new.xml"),
            "--out",
            str(tmp_path / "report.md"),
            "--impact",
            "urgent_magic",
        ],
    )

    assert result.exit_code == 1
    assert "--impact must be one of" in result.output


def test_cli_packet_generates_complete_packet(tmp_path: Path):
    out = tmp_path / "packet"

    result = runner.invoke(
        app,
        [
            "packet",
            str(ROOT / "examples" / "sample_input" / "old.xml"),
            str(ROOT / "examples" / "sample_input" / "new.xml"),
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 0
    assert "Start here" in result.output
    assert (out / "change-brief.md").exists()
    assert (out / "manager-summary.md").exists()
    assert (out / "remediation-backlog.csv").exists()
    assert (out / "jira-import.csv").exists()
    assert (out / "servicenow-import.csv").exists()
    assert (out / "github-issues.md").exists()


def test_cli_batch_generates_portfolio_packet(tmp_path: Path):
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    out = tmp_path / "portfolio"
    old_dir.mkdir()
    new_dir.mkdir()
    shutil.copy(ROOT / "examples" / "sample_input" / "old.xml", old_dir / "synthetic.xml")
    shutil.copy(ROOT / "examples" / "sample_input" / "new.xml", new_dir / "synthetic.xml")

    result = runner.invoke(app, ["batch", str(old_dir), str(new_dir), "--out", str(out)])

    assert result.exit_code == 0
    assert "Start here" in result.output
    assert (out / "portfolio-summary.md").exists()
    assert (out / "synthetic-windows-and-linux-stig" / "change-brief.md").exists()


def test_cli_batch_requires_matching_titles(tmp_path: Path):
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    out = tmp_path / "portfolio"
    old_dir.mkdir()
    new_dir.mkdir()
    shutil.copy(ROOT / "examples" / "sample_input" / "old.xml", old_dir / "synthetic.xml")
    shutil.copy(ROOT / "examples" / "chrome_windows_sample" / "new.xml", new_dir / "chrome.xml")

    result = runner.invoke(app, ["batch", str(old_dir), str(new_dir), "--out", str(out)])

    assert result.exit_code == 1
    assert "no matching STIG titles" in result.output


def test_cli_invalid_xml_gives_clean_error(tmp_path: Path):
    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("<Benchmark><Group></Benchmark>", encoding="utf-8")

    result = runner.invoke(app, ["parse", str(bad_xml)])

    assert result.exit_code == 1
    assert "Invalid XML" in result.output


def test_cli_doctor_runs():
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "STIGPilot Doctor" in result.output


def test_cli_config_example_writes_file(tmp_path: Path):
    out = tmp_path / "stigpilot.toml"

    result = runner.invoke(app, ["config-example", "--out", str(out)])

    assert result.exit_code == 0
    assert "owner_rules" in out.read_text(encoding="utf-8")


def test_cli_chrome_demo_missing_official_files_uses_sample(tmp_path: Path):
    out = tmp_path / "chrome"
    missing_inputs = tmp_path / "missing-official"

    result = runner.invoke(app, ["chrome-demo", "--out", str(out), "--input-dir", str(missing_inputs)])

    assert result.exit_code == 0
    assert "Official Chrome STIG files were not found" in result.output
    assert "Start here" in result.output
    assert (out / "change-brief.md").exists()
    assert (out / "manager-summary.md").exists()
    assert (out / "remediation-backlog.csv").exists()


def test_cli_chrome_demo_can_filter_by_impact_and_owner(tmp_path: Path):
    out = tmp_path / "chrome-filtered"
    missing_inputs = tmp_path / "missing-official"

    result = runner.invoke(
        app,
        [
            "chrome-demo",
            "--out",
            str(out),
            "--input-dir",
            str(missing_inputs),
            "--impact",
            "evidence_update_likely",
            "--owner",
            "Endpoint/Windows Admin",
        ],
    )

    assert result.exit_code == 0
    text = (out / "change-brief.md").read_text(encoding="utf-8")
    assert "Chrome password manager must be disabled" in text
    assert "Chrome Safe Browsing enhanced protection" not in text
