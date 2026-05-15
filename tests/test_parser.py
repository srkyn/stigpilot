from pathlib import Path

from stigpilot.parser import parse_stig


FIXTURE = Path(__file__).parent / "fixtures_old.xml"


def test_parse_stig_extracts_core_fields():
    document = parse_stig(FIXTURE)

    assert document.title == "Synthetic Application STIG"
    assert document.version == "V1R1"
    assert document.release == "Release 1 (2026-01-01)"
    assert len(document.controls) == 3

    control = document.controls[0]
    assert control.vuln_id == "V-100001"
    assert control.rule_id == "SV-100001r1_rule"
    assert control.group_id == "V-100001"
    assert control.stig_id == "APP-STIG-000001"
    assert control.severity == "medium"
    assert control.cci_refs == ["CCI-000001"]
    assert "Local Security Policy" in control.check_text
    assert "GPO" in control.fix_text
    assert "Windows" in control.tags
    assert "GPO" in control.tags


def test_parser_tolerates_namespaced_new_fixture():
    document = parse_stig(Path(__file__).parent / "fixtures_new.xml")

    assert len(document.controls) == 3
    assert document.controls[0].vuln_id == "V-100001"
    assert document.controls[2].severity == "high"


def test_parser_extracts_rule_version_as_stig_id_from_demo_fixture():
    document = parse_stig(Path(__file__).parents[1] / "examples" / "sample_input" / "new.xml")

    assert document.controls[0].stig_id == "APP-AU-000001"
    assert any("VulnDiscussion" in ref for ref in document.controls[0].references)


def test_parser_extracts_nested_description_metadata(tmp_path: Path):
    xml_path = tmp_path / "nested-description.xml"
    xml_path.write_text(
        """
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>Nested Description STIG</title>
  <Group id="V-200001">
    <Rule id="SV-200001r1_rule" severity="medium">
      <title>Nested metadata rule</title>
      <description>
        <VulnDiscussion>Nested discussion text should be retained.</VulnDiscussion>
        <Mitigations>Nested mitigation text should be retained.</Mitigations>
      </description>
    </Rule>
  </Group>
</Benchmark>
""".strip(),
        encoding="utf-8",
    )

    document = parse_stig(xml_path)

    assert "VulnDiscussion: Nested discussion text should be retained." in document.controls[0].references
    assert "Mitigations: Nested mitigation text should be retained." in document.controls[0].references


def test_parser_missing_optional_fields_do_not_crash(tmp_path: Path):
    xml_path = tmp_path / "missing-fields.xml"
    xml_path.write_text(
        """
<Benchmark>
  <Group id="V-300001">
    <Rule id="SV-300001r1_rule" />
  </Group>
</Benchmark>
""".strip(),
        encoding="utf-8",
    )

    document = parse_stig(xml_path)

    assert len(document.controls) == 1
    assert document.controls[0].title == ""
    assert document.controls[0].check_text == ""
    assert document.controls[0].fix_text == ""
    assert document.controls[0].cci_refs == []
