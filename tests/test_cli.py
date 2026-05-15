from pathlib import Path

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
