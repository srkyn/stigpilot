# Changelog

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
