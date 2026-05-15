# STIGPilot

Navigate DISA STIG changes, remediation planning, and ticket-ready reporting.

STIGPilot is a Python CLI that turns STIG XCCDF/XML updates into analyst-ready change intelligence: what changed, what matters, who should review it, what ticket should be created, and what evidence should be collected.

It is intentionally narrow. It does not scan systems, validate compliance, auto-remediate hosts, or replace official tooling.

## Why It Exists

Official tools are authoritative for viewing STIGs, scanning systems, managing checklists, applying baselines, and supporting formal compliance workflows. STIGPilot solves a different operational problem:

> A new STIG release dropped. What changed, who needs to act, and what work should be queued?

The tool is useful when an analyst, sysadmin, vulnerability management team, or GRC person needs a fast, local way to compare releases and turn changes into reviewable work.

## Why Not Just Use Official Tools?

Use official DISA tools, SCC, SCAP validation, STIG Viewer, PowerSTIG, OpenRMF, and your organization’s compliance process for authoritative assessment work.

Use STIGPilot as a helper layer for:

- STIG version diffing
- implementation impact triage
- remediation backlog preparation
- evidence request planning
- ticket-friendly exports
- manager-readable summaries

STIGPilot does not claim compliance, certification, endorsement, or validation.

## Features

- Parse common XCCDF/XML STIG structures with namespace-tolerant XML handling.
- Extract Vuln ID, Rule ID, Group ID, STIG ID/version, title, severity, check text, fix text, CCI references, references, release metadata, and transparent tags.
- Export parsed controls to CSV and JSON.
- Generate single-STIG Markdown briefs.
- Compare old/new STIG files and detect added, removed, modified, severity, check text, fix text, CCI, and reference changes.
- Classify changes with explainable rule-based impact:
  - `high_priority_review`
  - `implementation_change_likely`
  - `evidence_update_likely`
  - `review_recommended`
  - `no_action_likely`
- Generate remediation backlog CSVs, evidence checklists, Jira-friendly CSVs, ServiceNow-friendly CSVs, GitHub issue draft Markdown, and ticket-friendly CSVs.
- Assign keyword-based tags such as Windows, Linux, GPO, Registry, Audit Logging, IAM, Remote Access, Network Security, Database, Cloud, and Container/Kubernetes.
- Suggest likely owners using transparent keyword rules.

## Install

```powershell
cd C:\Users\Admin\Documents\CSProjects\stigpilot
python -m pip install -r requirements.txt
python -m pip install -e .
```

Development mode without installing:

```powershell
python -m stigpilot.cli --help
```

On Windows, `pip` may warn that the Python user Scripts directory is not on `PATH`. If the `stigpilot` command is not recognized, either add that Scripts directory to `PATH` or use the module form:

```powershell
python -m stigpilot.cli demo
```

## One-Command Demo

```powershell
stigpilot demo
```

Or during development:

```powershell
python -m stigpilot.cli demo
```

The demo writes sanitized sample reports under `output/demo/`. Start with:

- `output/demo/change-brief.md`
- `output/demo/remediation-backlog.csv`
- `output/demo/evidence-checklist.md`
- `output/demo/jira-import.csv`
- `output/demo/servicenow-import.csv`
- `output/demo/github-issues.md`

## CLI Usage

Parse a STIG:

```powershell
stigpilot parse examples/sample_input/new.xml --csv output/controls.csv --json output/controls.json
```

Generate a brief:

```powershell
stigpilot brief examples/sample_input/new.xml --out output/brief.md --severity high
```

Compare two STIG versions:

```powershell
stigpilot diff examples/sample_input/old.xml examples/sample_input/new.xml --out output/change-brief.md --csv output/remediation-backlog.csv
```

Generate workflow exports:

```powershell
stigpilot diff examples/sample_input/old.xml examples/sample_input/new.xml --out output/change-brief.md --csv output/remediation-backlog.csv --jira-csv output/jira.csv --servicenow-csv output/servicenow.csv --github-md output/github-issues.md
```

Generate ticket-ready export from one STIG:

```powershell
stigpilot tickets examples/sample_input/new.xml --out output/tickets.csv --severity high
```

Generate an evidence checklist:

```powershell
stigpilot evidence examples/sample_input/new.xml --out output/evidence-checklist.md
```

Show a terminal summary:

```powershell
stigpilot summary examples/sample_input/new.xml
```

## Example Output

Synthetic fixtures are included in `examples/sample_input/`. They are fake and sanitized.

The committed sample outputs in `examples/sample_output/` include:

- `change-brief.md`
- `remediation-backlog.csv`
- `evidence-checklist.md`
- `jira-import.csv`
- `servicenow-import.csv`
- `github-issues.md`
- `controls.csv`
- `controls.json`

Example change brief excerpt:

```text
4 control change(s) were detected. 3 likely require priority review, implementation work, or evidence updates.
```

## Impact Rules

The classifier is intentionally transparent:

- New high severity control: `high_priority_review`
- Severity increased to high: `high_priority_review`
- Severity increased below high: `review_recommended`
- Meaningful fix text change: `implementation_change_likely`
- Meaningful check text change: `evidence_update_likely`
- Removed control: `review_recommended`
- Only title wording changed: `no_action_likely`
- CCI/reference changes: `review_recommended`

“Meaningful” text changes are based on simple text similarity and configuration-language keywords. There is no opaque AI dependency.

## Tags and Ownership

Tags and suggested owners are keyword-based and explainable. Examples:

- Windows, GPO, Registry, Defender/AV: Endpoint/Windows Admin
- Linux, sshd, sudo, auditd, PAM: Linux Admin
- SQL, Oracle, PostgreSQL, MongoDB: Database Admin
- Firewall, router, switch, Cisco, Palo Alto: Network/Security Engineering
- Cloud, Azure, AWS, GCP, Entra: Cloud/IAM Admin
- Container, Kubernetes, Docker: Platform/Container Admin

Everything else defaults to Security/GRC Analyst.

## Limitations

- STIGPilot does not validate host compliance.
- STIGPilot does not replace formal review.
- STIGPilot does not download or scrape DISA content.
- STIGPilot does not auto-remediate.
- XML variants are handled best-effort; unusual vendor packaging may require parser improvements.
- Keyword tags and owner mapping are transparent but imperfect.

## Safe Usage

Use STIGPilot only with files you are authorized to process. Do not publish sensitive evidence, system names, internal host data, credentials, classified information, or restricted organizational material. The included fixtures are synthetic.

## Roadmap

- Configurable owner/tag mappings with a local YAML or TOML file.
- Folder-level old/new STIG comparison for release bundles.
- Manager-only summary reports.
- Implementation-only and evidence-only filtered reports.
- HTML report output.
- Optional Streamlit dashboard after the CLI remains strong.

## What This Demonstrates

- Defensive security product judgment
- XCCDF/XML parsing with namespace resilience
- STIG release change analysis
- Rule-based impact classification
- Ticket and evidence workflow design
- Testable Python CLI engineering

## Development

Run tests:

```powershell
python -m pytest
```

Regenerate sample outputs:

```powershell
python -m stigpilot.cli diff examples\sample_input\old.xml examples\sample_input\new.xml --out examples\sample_output\change-brief.md --csv examples\sample_output\remediation-backlog.csv --jira-csv examples\sample_output\jira-import.csv --servicenow-csv examples\sample_output\servicenow-import.csv --github-md examples\sample_output\github-issues.md
python -m stigpilot.cli parse examples\sample_input\new.xml --csv examples\sample_output\controls.csv --json examples\sample_output\controls.json
python -m stigpilot.cli evidence examples\sample_input\new.xml --out examples\sample_output\evidence-checklist.md
```
