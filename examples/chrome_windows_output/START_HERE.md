# STIGPilot Packet

Start here if someone handed you this folder and you need to know what matters.

## Summary

- Old controls: 3
- New controls: 3
- Total changes: 4
- Added controls: 1
- Removed controls: 1
- Modified controls: 2
- Severity changes: 1
- High-priority review: 2
- Implementation change likely: 0
- Evidence update likely: 1

## Open These First

1. `change-brief.md` for analyst triage and priority actions.
2. `manager-summary.md` for a short leadership readout.
3. `remediation-backlog.csv` for backlog grooming or ticket prep.
4. `evidence-checklist.md` when validation steps or evidence requests need refresh.

## File Map

| File | Use it for |
| --- | --- |
| `change-brief.md` | Analyst-ready change summary and detailed changed-control table. |
| `change-brief.html` | Self-contained browser-friendly version of the change brief. |
| `changes.json` | Machine-readable export for local automation or review. |
| `manager-summary.md` | Short readout for managers and team leads. |
| `remediation-backlog.csv` | CSV backlog for triage, ownership, notes, and status tracking. |
| `evidence-checklist.md` | Owner-grouped evidence requests and validation metadata. |
| `jira-import.csv` | Local CSV shaped for Jira import review. |
| `servicenow-import.csv` | Local CSV shaped for ServiceNow import review. |
| `github-issues.md` | Copy-paste-ready Markdown issue drafts. |
| `remediation-drafts.md` | Review-only implementation notes. STIGPilot does not apply changes. |

## Top Actions

1. `V-CHROME-001` - Chrome Safe Browsing enhanced protection must be enabled (High-priority review, Endpoint/Windows Admin): The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review.
2. `V-CHROME-004` - Chrome extension installation must be restricted (High-priority review, Endpoint/Windows Admin): A new high-severity control was added, so it should be triaged before lower-risk backlog work.
3. `V-CHROME-002` - Chrome password manager must be disabled (Evidence update likely, Endpoint/Windows Admin): The check procedure changed enough that evidence requests or validation steps may need to be refreshed.
4. `V-CHROME-003` - Deprecated Chrome cleanup policy must be reviewed (Review recommended, Security/GRC Analyst): The control was removed, so downstream tickets, evidence requests, or mappings may need cleanup.

## Reminder

STIGPilot is a local workflow helper for change triage, remediation planning, evidence preparation, and ticket exports. It does not scan systems, validate compliance, or replace official DISA tooling.
