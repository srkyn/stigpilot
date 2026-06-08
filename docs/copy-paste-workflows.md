# Copy-Paste Workflows

Use these as quick starting points. Replace `old.xml` and `new.xml` with the XCCDF files from the older and newer STIG releases.

## Security Analyst

Goal: understand what changed and what needs review first.

```bash
stigpilot packet old.xml new.xml --out output/stig-review
```

Open these first:

- `output/stig-review/change-brief.md`
- `output/stig-review/remediation-backlog.csv`
- `output/stig-review/github-issues.md`

What to look for:

- Severity increases
- New high-severity controls
- Remediation text changes
- Controls that look like wording or reference churn

## Sysadmin Or Engineering Team

Goal: get only the work likely owned by one team.

```bash
stigpilot diff old.xml new.xml `
  --out output/windows-high-priority.md `
  --csv output/windows-high-priority.csv `
  --impact high_priority_review `
  --owner "Endpoint/Windows Admin"
```

For Linux-owned work:

```bash
stigpilot diff old.xml new.xml `
  --out output/linux-review.md `
  --csv output/linux-review.csv `
  --owner "Linux Admin"
```

What to look for:

- Controls where fix text changed
- Controls where validation evidence changed
- Any change that requires GPO, registry, auditd, sshd, PAM, sudo, firewall, database, or cloud policy review

## GRC Or Evidence Owner

Goal: refresh evidence requests without reading every control manually.

```bash
stigpilot evidence new.xml --out output/evidence-checklist.md
```

For release-to-release evidence changes:

```bash
stigpilot diff old.xml new.xml `
  --out output/evidence-changes.md `
  --csv output/evidence-backlog.csv `
  --impact evidence_update_likely
```

Open these first:

- `output/evidence-checklist.md`
- `output/evidence-changes.md`
- `output/evidence-backlog.csv`

## Manager Or Team Lead

Goal: get a short readout without opening the full STIG.

```bash
stigpilot manager old.xml new.xml --out output/manager-summary.md
```

Open:

- `output/manager-summary.md`

What to look for:

- Total workload
- Most affected owner groups
- High-priority review count
- Implementation-review count
- Evidence-refresh count

## Ticket Import Prep

Goal: create local files that can be reviewed before import.

```bash
stigpilot diff old.xml new.xml `
  --out output/change-brief.md `
  --csv output/remediation-backlog.csv `
  --jira-csv output/jira-import.csv `
  --servicenow-csv output/servicenow-import.csv `
  --github-md output/github-issues.md `
  --drafts-md output/remediation-drafts.md `
  --json output/changes.json
```

Review before importing:

- `output/remediation-backlog.csv`
- `output/jira-import.csv`
- `output/servicenow-import.csv`
- `output/github-issues.md`

## Government Mode

Goal: generate a local packet on a locked-down Windows host without Python.

```powershell
.\tools\STIGPilot-Gov.ps1 -Command doctor
.\tools\STIGPilot-Gov.ps1 -Command packet -Old old.xml -New new.xml -OutDir output\gov
```

Or use the launcher:

```powershell
tools\STIGPilot.cmd -Command packet -Old old.xml -New new.xml -OutDir output\gov
```

Open these first:

- `output/gov/change-brief.md`
- `output/gov/remediation-backlog.csv`
- `output/gov/evidence-checklist.md`
