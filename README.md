# STIGPilot

Navigate DISA STIG changes, remediation planning, and ticket-ready reporting.

STIGPilot is a lightweight Python CLI for answering the operational questions that appear when a new STIG release drops:

- What changed?
- What matters?
- Who should look at it?
- What ticket should be created?
- What evidence should be collected?
- What can be summarized for an analyst, admin, or manager?

Official tools are authoritative. STIGPilot is a helper layer focused on change analysis, remediation planning, evidence collection, and ticket-ready exports.

## Disclaimer

STIGPilot does not replace official DISA tools, DISA STIG Viewer, SCC, SCAP validation, PowerSTIG, OpenRMF, formal compliance review, or authoritative assessment workflows. It does not scan systems, validate compliance, auto-remediate hosts, or claim official endorsement.

Use it to organize change intelligence and remediation work. Use official sources and approved organizational processes for compliance decisions.

## Features

- Parse XCCDF/XML STIG content with resilient namespace handling.
- Extract Vuln ID, Rule ID, Group ID, STIG ID, title, severity, check text, fix text, CCI references, external references, version, and release metadata.
- Export normalized controls to CSV and JSON.
- Generate a single-STIG Markdown brief.
- Compare two STIG versions and detect added, removed, modified, and severity-changed controls.
- Identify title, severity, check text, fix text, CCI, and reference changes.
- Classify impact with transparent rules:
  - `no_action_likely`
  - `review_recommended`
  - `evidence_update_likely`
  - `implementation_change_likely`
  - `high_priority_review`
- Generate Markdown change briefs, remediation backlog CSVs, evidence checklists, and ticket-ready CSV exports.
- Suggest owners from control language, such as Windows, Linux, database, and network/security engineering teams.

## Install

```powershell
cd C:\Users\Admin\Documents\CSProjects\stigpilot
python -m pip install -r requirements.txt
python -m pip install -e .
```

You can also run the CLI during development without installing:

```powershell
python -m stigpilot.cli --help
```

## CLI Usage

Parse a STIG and export controls:

```powershell
stigpilot parse input.xml --csv output.csv --json output.json
```

Generate a single-STIG brief:

```powershell
stigpilot brief input.xml --out report.md --severity high
```

Compare two STIG versions:

```powershell
stigpilot diff old.xml new.xml --out change-brief.md --csv remediation-backlog.csv
```

Generate ticket-ready export:

```powershell
stigpilot tickets input.xml --out tickets.csv --severity high
```

Generate an evidence checklist:

```powershell
stigpilot evidence input.xml --out evidence-checklist.md
```

Show a terminal summary:

```powershell
stigpilot summary input.xml
```

## Example Outputs

Synthetic sample inputs are included in `examples/sample_input/`. They are not real DISA content.

```powershell
python -m stigpilot.cli parse examples\sample_input\synthetic_new.xml --csv examples\sample_output\controls.csv --json examples\sample_output\controls.json
python -m stigpilot.cli brief examples\sample_input\synthetic_new.xml --out examples\sample_output\brief.md --severity high
python -m stigpilot.cli diff examples\sample_input\synthetic_old.xml examples\sample_input\synthetic_new.xml --out examples\sample_output\change-brief.md --csv examples\sample_output\remediation-backlog.csv
python -m stigpilot.cli tickets examples\sample_input\synthetic_new.xml --out examples\sample_output\tickets.csv --severity high
python -m stigpilot.cli evidence examples\sample_input\synthetic_new.xml --out examples\sample_output\evidence-checklist.md
python -m stigpilot.cli summary examples\sample_input\synthetic_new.xml
```

Generated examples include:

- `examples/sample_output/controls.csv`
- `examples/sample_output/controls.json`
- `examples/sample_output/brief.md`
- `examples/sample_output/change-brief.md`
- `examples/sample_output/remediation-backlog.csv`
- `examples/sample_output/tickets.csv`
- `examples/sample_output/evidence-checklist.md`

## Impact Rules

The MVP uses simple, auditable logic:

- Severity changed to high, or a high severity control was added: `high_priority_review`
- Fix text changed: `implementation_change_likely`
- Check text changed without fix text changing: `evidence_update_likely`
- Removed control: `review_recommended`
- CCI or reference changed: `review_recommended`
- Only title changed: `no_action_likely`

These rules are intentionally transparent so teams can tune them later.

## Screenshots

Placeholder for future terminal screenshots and sample report captures.

## Roadmap

- Configurable impact and owner rules.
- Optional Jinja2 report templates.
- Richer release metadata extraction across more STIG packaging variants.
- GitHub Issues, Jira, or ServiceNow export adapters.
- HTML report output.
- Control family and CCI mapping summaries.
- Optional local caching of known STIG parse results.

## Portfolio Value

STIGPilot demonstrates practical cybersecurity automation without pretending to be a scanner or compliance authority. It shows:

- Defensive security domain modeling.
- XML/XCCDF parsing with namespace resilience.
- Change intelligence and analyst-friendly reporting.
- Rule-based triage and ticket shaping.
- Testable Python CLI design with clean module boundaries.

## Safe and Legal Usage

Use STIGPilot only with files you are authorized to process. Do not include sensitive system data, classified information, credentials, or restricted organizational evidence in public repositories. The sample fixtures in this project are synthetic.

## Development

Run tests:

```powershell
python -m pytest
```

Project layout:

```text
stigpilot/
  stigpilot/
    cli.py
    parser.py
    models.py
    diff.py
    impact.py
    exporters.py
    reports.py
    utils.py
  examples/
  tests/
```
