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
- Produce Jira CSV, ServiceNow CSV, and GitHub issue Markdown drafts

It is intentionally smaller than the Python CLI. It is a fallback for locked-down Windows environments, not a replacement for the full STIGPilot experience.

## Getting Your STIG Files

STIGPilot works with XCCDF XML files from DISA. Here is how to get them:

1. Go to [https://public.cyber.mil/stigs/downloads/](https://public.cyber.mil/stigs/downloads/)
2. Search for the STIG you need, for example, "Windows 11", "Google Chrome", or "Red Hat"
3. Download two ZIP files: the current release and the previous release
4. Extract each ZIP
5. Inside each extracted folder, find the file whose name ends in `_Manual-xccdf.xml`.
   That is the file STIGPilot needs.
6. Use the older release file as `-Old` and the newer release file as `-New`

**Example with Google Chrome:**
- Download `U_Google_Chrome_V2R10_STIG.zip` and `U_Google_Chrome_V2R11_STIG.zip`
- Extract both
- Find `U_Google_Chrome_Current_Windows_V2R10_STIG_Manual-xccdf.xml` (old)
- Find `U_Google_Chrome_Current_Windows_V2R11_STIG_Manual-xccdf.xml` (new)
- Run: `.\tools\STIGPilot.cmd -Command packet -Old old.xml -New new.xml -OutDir output\chrome`

The XCCDF file is the one that starts with your STIG name and ends in `xccdf.xml`.
It is not the benchmark zip, the checklist file, or the SCAP content. It is just the
file with `Manual-xccdf` in the name.

## Quick Start

From the repository root:

```powershell
.\tools\STIGPilot-Gov.ps1 -Command doctor
```

The doctor command checks PowerShell, built-in XML support, sample files, parser behavior, diff behavior, and output writability.

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
output/gov/jira-import.csv
output/gov/servicenow-import.csv
output/gov/github-issues.md
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

## Generate a Focused Packet

Use `-Impact` and `-Owner` when a Windows, Linux, GRC, or network team only needs its slice of the change packet:

```powershell
.\tools\STIGPilot-Gov.ps1 -Command packet `
  -Old examples\sample_input\old.xml `
  -New examples\sample_input\new.xml `
  -OutDir output\gov-windows `
  -Impact high_priority_review `
  -Owner "Endpoint/Windows Admin"
```

Allowed impact filters:

- `high_priority_review`
- `implementation_change_likely`
- `evidence_update_likely`
- `review_recommended`
- `no_action_likely`

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

## Ticket Exports

The `packet` command writes local ticket-friendly files without connecting to Jira, ServiceNow, GitHub, or any external API:

- `jira-import.csv`
- `servicenow-import.csv`
- `github-issues.md`

These files are intentionally plain local exports. Review them before importing into a ticketing system, especially in environments with formal change-control or records-management requirements.

## Why PowerShell

Many Windows government environments already allow signed or reviewed PowerShell scripts for administrative work. A PowerShell fallback keeps the core STIGPilot workflow available in places where Python itself is considered third-party software.

If your environment requires signed scripts, review the source, sign it through your normal code-signing process, and run it under your organization's execution policy.
