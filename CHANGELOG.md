# Changelog

## 1.0.16

2026-06-08

- Added Government Mode `archive` to inspect a packet and create a ZIP archive with built-in PowerShell.
- Added Government Mode archive regression tests for success, overwrite protection, and incomplete packet refusal.
- Documented Government Mode packet archiving in the README.

## 1.0.15

2026-06-08

- Added `stigpilot archive-output` to validate a packet and create a ZIP archive for local handoff.
- Added archive regression tests for success, overwrite protection, and incomplete packet refusal.
- Documented packet archiving in the README packet workflow.

## 1.0.14

2026-06-08

- Added Government Mode `inspect` to check generated packet folders before handoff.
- Added Government Mode regression tests for complete and incomplete packet inspection.
- Documented Government Mode packet inspection in the README.

## 1.0.13

2026-06-08

- Added `stigpilot inspect-output` to check generated packet folders before handoff.
- Added CLI regression tests for complete and incomplete packet inspection.
- Documented packet inspection in the README packet workflow.

## 1.0.12

2026-06-08

- Added role-specific "Next 15 Minutes" guidance to generated Python and Government Mode packet indexes.
- Updated tests so packet indexes must include the role-action section.

## 1.0.11

2026-06-08

- Updated quickstart and README demo guidance to point users at `START_HERE.md` first.
- Added `START_HERE.md` to the sample packet file map.

## 1.0.10

2026-06-08

- Added `START_HERE.md` to Python comparison packets, demo output, Chrome demo output, portfolio sub-packets, and Government Mode packets.
- Updated tests so generated packets must include the packet index.
- Regenerated committed sample outputs with the new packet index.

## 1.0.9

2026-06-08

- Added role-based copy-paste workflows for analysts, sysadmins, GRC evidence owners, managers, ticket import prep, and Government Mode.
- Linked the workflow guide from the README.

## 1.0.8

2026-06-08

- Added a documentation link regression test so local README, docs, and example Markdown links point to real files.

## 1.0.7

2026-06-08

- Added a Python CLI vs Government Mode decision guide for restricted Windows and government environments.
- Linked the guide from the README and Government Mode documentation.

## 1.0.6

2026-06-08

- Added `stigpilot quickstart` with side-by-side Python CLI and Government Mode first-run commands.
- Updated README first-use docs with the quickstart command and a fenced Government Mode launcher example.
- Updated the release checklist to include quickstart, Government Mode doctor, and the one-command sample output regeneration script.

## 1.0.5

2026-06-08

- Added `tools/regenerate-examples.ps1` to refresh all committed demo and sample output packets with one command.
- Updated development docs so release prep does not depend on copying a long list of CLI commands by hand.
- Removed trailing whitespace from generated HTML change briefs.

## 1.0.4

2026-06-08

- Added `doctor` to Government Mode for a no-Python health check.
- Updated Government Mode help and docs so first-run users can verify PowerShell, sample XMLs, parser behavior, diff behavior, and output writability.
- Kept Government Mode help examples repo-relative and copy-friendly.

## 1.0.3

2026-06-08

- Updated the PyPI publish workflow to use current GitHub Actions versions and the existing development build dependency.
- Improved Government Mode terminal summaries with cleaner visual separation and aligned metrics.
- Fixed Government Mode change briefs so owner summaries prioritize high-priority and evidence-update work instead of arbitrary tie order.
- Improved Government Mode evidence checklists with checkbox metadata fields.

## 1.0.2

2026-06-08

- Hardened generated Markdown and ticket-draft outputs with plain analyst-friendly labels.
- Removed remote font loading from self-contained HTML change briefs.
- Fixed built-in Python demo metadata so committed sample JSON keeps repo-relative paths.
- Fixed Government Mode metadata so sample `changes.json` and parse JSON do not leak local machine paths.
- Added output-quality regression tests for committed sample packets, local path leakage, long dash punctuation, emoji status markers, and remote HTML assets.
- Regenerated committed sample outputs.

## 1.0.1

2026-05-31

- Added terminal demo GIFs to the README for `stigpilot demo`, `stigpilot chrome-demo`, and `stigpilot packet`.
- Added a PyPI version badge to the README.
- No tool behavior, output format, CSV, JSON, or Government Mode changes.

## 1.0.0

2026-05-31

- Remastered terminal, HTML, and Markdown reports with a meaning-driven visual system.
- Added risk-first terminal summaries, metric panels, and severity-aware Rich table styling.
- Added institutional HTML report styling with risk bars, semantic badges, priority cards, sticky navigation, dark mode, and print styles.
- Added scan-friendly Markdown risk statements, emoji severity labels, section dividers, and linkable priority action headings.
- No changes to CSV, JSON schemas, or Government Mode behavior.

## 0.9.3

2026-05-31

- Improved Government Mode accessibility for restricted and no-Python Windows environments.
- Made `tools/STIGPilot-Gov.ps1` friendlier when run standalone, with no-argument usage guidance and early parameter validation.
- Added `tools/STIGPilot.cmd` as a Command Prompt launcher with process-scoped execution policy bypass.
- Added a pre-generated sample packet under `docs/sample-packet/`.
- Documented how to source DISA XCCDF XML files and run Government Mode without cloning the repository.

## 0.9.2

2026-05-31

- Replaced the README banner reference with a PNG asset so PyPI's image proxy renders it reliably.
- No runtime changes.

## 0.9.1

2026-05-31

- Restored the package author contact email for clearer PyPI metadata.
- Kept the PyPI trusted publishing workflow and runtime dependency split unchanged.

## 0.9.0

2026-05-31

- Added review-only remediation draft generation.
- Added `--drafts-md` to `stigpilot diff`.
- Added `stigpilot drafts` for standalone remediation planning notes.
- Packet, batch, demo, and Chrome demo workflows now include `remediation-drafts.md`.
- Documented the remediation automation boundary.

## 0.8.2

- Added `-Impact` and `-Owner` filters to Government Mode `diff` and `packet` workflows.
- Added Government Mode validation for unknown impact filters.
- Documented focused Government Mode packets for team-specific review.
- Added regression coverage for filtered Government Mode packets.

## 0.8.1

- Added Jira CSV, ServiceNow CSV, and GitHub issue Markdown drafts to the Government Mode packet.
- Updated Government Mode documentation, README output lists, sample outputs, and regression coverage for ticket exports.

## 0.8.0

- Added Government Mode with `tools/STIGPilot-Gov.ps1`, a PowerShell-only fallback for restrictive Windows environments where Python may be considered third-party software.
- Added Government Mode documentation with parse, diff, packet, and evidence examples.
- Documented the Government Mode workflow in the README.
- Added regression coverage for the PowerShell fallback script and documentation.
- Added `schema_version` and schema path metadata to `changes.json`.
- Added a committed JSON Schema for machine-readable change exports.
- Documented the changes JSON schema contract in the README.

## 0.7.0

- Added machine-readable `changes.json` exports for automation workflows.
- Packet, batch, demo, and Chrome demo workflows now include `changes.json`.
- Added `--json` to `stigpilot diff` for standalone changes JSON export.
- Added JSON export regression coverage for CLI and exporter behavior.

## 0.6.1

- Added HTML change briefs to generated comparison packets.
- Packet, batch, and Chrome demo workflows now include `change-brief.html` alongside Markdown and CSV outputs.
- Updated README examples and CLI regression coverage for packet HTML output.

## 0.6.0

- Added `stigpilot html` for self-contained browser-readable change briefs.
- Added HTML report generation using the same impact, owner, and priority logic as Markdown reports.
- Added committed HTML sample output under `examples/html_output/`.
- Added CLI and report regression coverage for HTML output.

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
