# Remediation Boundary

STIGPilot stops at remediation planning by design.

It compares STIG releases, identifies meaningful control changes, assigns review impact, suggests owners, generates backlog CSVs, creates evidence checklists, and exports ticket-ready files. It does not apply registry changes, edit configuration files, modify GPOs, restart services, or change hosts.

## Why STIGPilot Does Not Apply Changes

STIG remediation is environment-specific. The same control can be implemented through local policy, Group Policy, MDM, configuration management, application policy, golden images, or compensating controls. Applying a generic patch without knowing that context can create outages, duplicate work, or break an approved exception.

The safer automation boundary is:

1. Parse the old and new STIG files.
2. Identify what changed.
3. Classify the likely impact.
4. Assign a likely owner.
5. Generate reviewable tickets, backlogs, manager summaries, and evidence requests.
6. Let the responsible team apply changes through its normal change-control path.

## What Automation Is Appropriate

Good automation for this project:

- Remediation backlog CSVs.
- Jira, ServiceNow, and GitHub issue drafts.
- Evidence checklists.
- Owner-focused packets.
- Machine-readable `changes.json` exports.
- Optional script or playbook drafts marked as review-only.

Risky automation for this project:

- Applying system changes directly.
- Editing Group Policy or MDM profiles.
- Changing registry keys on live hosts.
- Restarting services.
- Running remote commands.
- Treating STIG text as a universal patch.

## Future Safe Direction

A future command could generate review-only remediation stubs, such as PowerShell, Ansible, or policy notes, but those files should be disabled by default and clearly marked as drafts. They should require human review, local testing, rollback planning, and organizational approval before use.

The goal is not to avoid automation. The goal is to automate the part that should be consistent and leave the environment-specific decision with the operator.
