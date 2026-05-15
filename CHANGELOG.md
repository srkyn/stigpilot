# Changelog

## 0.5.1

- Added `--impact` and `--owner` filtering to `stigpilot chrome-demo`.
- Documented focused Chrome demo packets for team-specific review.
- Added CLI regression coverage for filtered Chrome demo output.

## 0.5.0

- Added `stigpilot packet` for one-command full workflow packet generation from two STIG XML files.
- The packet command writes the change brief, manager summary, remediation backlog, evidence checklist, Jira CSV, ServiceNow CSV, and GitHub issue drafts.
- Added CLI regression coverage for complete packet generation.

## 0.4.0

- Added `stigpilot batch` for folder-to-folder STIG release comparisons.
- Added portfolio summary generation with per-STIG report packets.
- Added sanitized portfolio input fixtures and committed generated portfolio outputs.
- Added CLI regression coverage for batch comparisons and unmatched-folder handling.

## 0.3.2

- Added focused `diff` and `manager` filters for impact category and suggested owner.
- Documented focused packet generation for analyst and owner-specific workflows.
- Added CLI regression coverage for impact/owner filtering and invalid impact filters.

## 0.3.1

- Replaced internal impact enum values with analyst-friendly labels in generated Markdown reports.
- Improved change brief priority actions with owner and "why it matters" context.
- Added manager-summary assumptions and limitations language to reinforce that STIGPilot supports triage, not formal validation.
- Added `Environment` metadata to evidence checklists.
- Regenerated sample and Chrome demo outputs with the polished report language.

## 0.3.0

- Added first-class `stigpilot chrome-demo` workflow.
- Removed vendored official Chrome STIG XML files; official XMLs are now user-supplied.
- Added sanitized Chrome sample fixtures so the Chrome demo works immediately.
- Added official Chrome file placement instructions under `examples/chrome_windows_input/`.
- Added release checklist documentation.
- Added CLI regression coverage for Chrome demo missing-file fallback.

## 0.2.1

- Added an official DoD Cyber Exchange Google Chrome for Windows V2R10-to-V2R11 comparison example.
- Added generated Chrome example change brief, manager summary, evidence checklist, backlog CSV, Jira CSV, ServiceNow CSV, GitHub issue drafts, and parsed controls.
- Added Browser Security keyword tagging.

## 0.2.0

- Reworked README for a stronger 60-second demo and clearer positioning.
- Added polished CLI summaries for `demo`, `diff`, and `manager`.
- Added `doctor` and `config-example` commands.
- Improved change briefs, manager summaries, evidence checklists, and GitHub issue drafts.
- Improved change-type detection and human-readable impact reasons.
- Improved owner/tag keyword coverage.
- Made CSV exports more Excel-friendly with practical headers.
- Added GitHub Actions CI, issue templates, CONTRIBUTING, and SECURITY docs.
- Expanded CLI, parser, report, and export tests.

## 0.1.1

- Added manager-facing STIG change summaries.
- Added configurable owner/tag mappings.
- Improved sample outputs and README positioning.
- Added `doctor` and `config-example` commands.
- Improved report readability, evidence checklists, and ticket exports.

## 0.1.0

- Initial MVP: parse STIG XCCDF/XML, export controls, diff releases, classify impact, and generate workflow reports.
