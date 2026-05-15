# LinkedIn Launch Draft

I built STIGPilot, a Python CLI for STIG change intelligence and remediation workflow planning.

It is not a STIG Viewer clone, scanner, auto-remediation tool, or replacement for official DISA tooling. The goal is narrower:

When a new STIG release drops, what changed, what matters, who needs to act, what ticket should be created, and what evidence should be collected?

Current MVP:

- Parses DISA-style XCCDF/XML.
- Exports normalized controls to CSV and JSON.
- Generates single-STIG Markdown briefs.
- Compares two STIG versions.
- Detects added, removed, severity, check text, fix text, CCI, and reference changes.
- Classifies likely impact with transparent rules.
- Produces remediation backlog CSVs, ticket-friendly CSVs, and evidence checklists.

The project is intentionally defensive and workflow-focused. Official DISA tools, SCC, SCAP validation, PowerSTIG, OpenRMF, and formal compliance review remain authoritative. STIGPilot is a helper layer for analysts and admins who need to turn release changes into reviewable work.

Repo: https://github.com/srkyn/stigpilot
Portfolio: https://srkyn.com/
