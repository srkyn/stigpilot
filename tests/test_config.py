from pathlib import Path

import pytest

from stigpilot.config import load_config
from stigpilot.models import StigControl
from stigpilot.parser import parse_stig
from stigpilot.taxonomy import suggested_owner, tags_for_control


def test_load_config_extends_owner_and_tag_rules(tmp_path: Path):
    config_path = tmp_path / "stigpilot.toml"
    config_path.write_text(
        """
[[owner_rules]]
owner = "Identity Team"
keywords = ["privileged account"]

[tag_rules]
"Privileged Access" = ["privileged account"]
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_path)
    control = StigControl(title="Privileged account review must be documented")

    assert suggested_owner(control, config) == "Identity Team"
    assert "Privileged Access" in tags_for_control(control, config)


def test_parse_stig_applies_config_tags(tmp_path: Path):
    config_path = tmp_path / "stigpilot.toml"
    config_path.write_text(
        """
[tag_rules]
"Evidence Refresh" = ["export applied"]
""".strip(),
        encoding="utf-8",
    )

    document = parse_stig(Path(__file__).parent / "fixtures_new.xml", load_config(config_path))

    assert "Evidence Refresh" in document.controls[0].tags


def test_load_config_rejects_bad_owner_rules(tmp_path: Path):
    config_path = tmp_path / "bad.toml"
    config_path.write_text('owner_rules = "Security Team"', encoding="utf-8")

    with pytest.raises(ValueError, match="owner_rules"):
        load_config(config_path)
