# STIGPilot Government Mode Packet

Start here if someone handed you this folder and you need to know what matters.

## Summary

- Old controls: 3
- New controls: 3
- Total changes: 4
- Added controls: 1
- Removed controls: 1
- Modified controls: 2
- Severity increases: 1
- High-priority review: 2
- Implementation change likely: 0
- Evidence update likely: 1

## Open These First

1. `change-brief.md` for analyst triage and priority actions.
2. `remediation-backlog.csv` for backlog grooming or ticket prep.
3. `evidence-checklist.md` when validation steps or evidence requests need refresh.
4. `github-issues.md` for copy-paste-ready issue drafts.

## Next 15 Minutes

| Role | Do this first |
| --- | --- |
| Security analyst | Read `change-brief.md`, then mark the high-priority and implementation-likely rows in `remediation-backlog.csv`. |
| Sysadmin or engineer | Filter `remediation-backlog.csv` by your owner group, then review changed fix text before reusing old implementation notes. |
| GRC or evidence owner | Open `evidence-checklist.md` and refresh requests for controls marked evidence update likely. |
| Manager or lead | Use the summary counts and top actions to decide which team needs the first review block. |

## File Map

| File | Use it for |
| --- | --- |
| `change-brief.md` | Analyst-ready change summary and detailed changed-control table. |
| `remediation-backlog.csv` | CSV backlog for triage, ownership, notes, and status tracking. |
| `changes.json` | Machine-readable export for local automation or review. |
| `evidence-checklist.md` | Owner-grouped evidence requests and validation metadata. |
| `jira-import.csv` | Local CSV shaped for Jira import review. |
| `servicenow-import.csv` | Local CSV shaped for ServiceNow import review. |
| `github-issues.md` | Copy-paste-ready Markdown issue drafts. |

## Top Actions

1. `V-100001` - Windows audit policy must be configured and reviewed (High-priority review, Endpoint/Windows Admin): The severity increased, so the control should be reviewed before reusing old risk notes, tickets, or evidence.
2. `V-100004` - Firewall management access must be restricted (High-priority review, Network/Security Engineering): A new high-severity control was added, so it should be reviewed before lower-risk backlog items.
3. `V-100002` - Linux SSH banner must be configured (Evidence update likely, Linux Admin): The validation steps changed enough that evidence requests may need to be refreshed.
4. `V-100003` - Removed database audit control (Review recommended, Database Admin): The control was removed from the newer file; review whether open tickets or evidence requests can be closed or retired.

## Reminder

STIGPilot Government Mode is a local workflow helper for change triage, remediation planning, evidence preparation, and ticket exports. It does not scan systems, validate compliance, or replace official DISA tooling.
