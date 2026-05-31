# STIGPilot Sample Packet

This is a complete pre-generated STIGPilot output packet from the synthetic
Chrome demo data included in the repository.

No installation required to view these files. Open them directly to see
what STIGPilot produces before running it in your environment.

## Files

| File | What it is |
|---|---|
| `change-brief.md` | Analyst-facing summary of what changed and what likely needs attention |
| `manager-summary.md` | Non-technical summary for managers and stakeholders |
| `remediation-backlog.csv` | Backlog of controls that likely need remediation work, importable to Excel |
| `evidence-checklist.md` | List of evidence items that may need refresh |
| `jira-import.csv` | Ready to import into Jira as tasks |
| `servicenow-import.csv` | Ready to import into ServiceNow as change requests |
| `github-issues.md` | GitHub issue drafts for tracking remediation work |
| `changes.json` | Machine-readable change export for automation workflows |

## Source

Generated from `examples/sample_input/old.xml` and `examples/sample_input/new.xml`
using `stigpilot packet`. The input files are synthetic and sanitized.

To generate your own packet from real STIG files:
- Python: `stigpilot packet old.xml new.xml --out output/packet`
- PowerShell (no Python): `.\tools\STIGPilot.cmd -Command packet -Old old.xml -New new.xml -OutDir output\packet`
