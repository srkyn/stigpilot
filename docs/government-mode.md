# STIGPilot Government Mode

Some government and regulated environments treat Python, pip packages, and open-source dependencies as third-party software that require separate approval. STIGPilot's primary CLI is still the best experience, but the repository also includes a PowerShell-only fallback for Windows environments where built-in tools are easier to approve.

Government Mode is located at:

```text
tools/STIGPilot-Gov.ps1
```

It uses only built-in PowerShell and .NET capabilities:

- XML parsing through `System.Xml.XmlDocument`
- CSV export through `Export-Csv`
- JSON export through `ConvertTo-Json`
- Markdown generation through local file writes

It does not require Python, pip, Typer, Rich, internet access, or external modules.

## What It Supports

Government Mode focuses on the same core workflow as STIGPilot:

- Parse a STIG XCCDF/XML file
- Compare old and new STIG XML files
- Detect added, removed, modified, and severity-increased controls
- Produce a Markdown change brief
- Produce a remediation backlog CSV
- Produce a Markdown evidence checklist
- Produce a machine-readable `changes.json`

It is intentionally smaller than the Python CLI. It is a fallback for locked-down Windows environments, not a replacement for the full STIGPilot experience.

## Quick Start

From the repository root:

```powershell
.\tools\STIGPilot-Gov.ps1 -Command packet `
  -Old examples\sample_input\old.xml `
  -New examples\sample_input\new.xml `
  -OutDir output\gov
```

Generated files:

```text
output/gov/change-brief.md
output/gov/remediation-backlog.csv
output/gov/changes.json
output/gov/evidence-checklist.md
```

## Parse One STIG

```powershell
.\tools\STIGPilot-Gov.ps1 -Command parse `
  -Input examples\sample_input\new.xml `
  -Csv output\gov\controls.csv `
  -Json output\gov\controls.json
```

## Compare Two STIG Releases

```powershell
.\tools\STIGPilot-Gov.ps1 -Command diff `
  -Old examples\sample_input\old.xml `
  -New examples\sample_input\new.xml `
  -Markdown output\gov\change-brief.md `
  -Csv output\gov\remediation-backlog.csv
```

## Generate Evidence Checklist

```powershell
.\tools\STIGPilot-Gov.ps1 -Command evidence `
  -Input examples\sample_input\new.xml `
  -Markdown output\gov\evidence-checklist.md
```

## Scope and Limitations

Government Mode is a local workflow helper. It does not:

- Scan systems
- Validate STIG compliance
- Replace DISA STIG Viewer, SCC, SCAP tooling, PowerSTIG, OpenRMF, or formal review
- Apply remediations
- Download official STIG content

Use official tools and your organization's compliance process for authoritative validation. Use Government Mode when you need a lightweight local packet that helps answer what changed, what likely matters, who owns the work, and what evidence should be refreshed.

## Why PowerShell

Many Windows government environments already allow signed or reviewed PowerShell scripts for administrative work. A PowerShell fallback keeps the core STIGPilot workflow available in places where Python itself is considered third-party software.

If your environment requires signed scripts, review the source, sign it through your normal code-signing process, and run it under your organization's execution policy.
