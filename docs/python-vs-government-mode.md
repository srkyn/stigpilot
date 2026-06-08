# Python CLI vs Government Mode

STIGPilot has two local ways to generate a STIG change packet. Pick the one that fits your environment and approval path.

## Short Answer

Use the Python CLI when Python is allowed. Use Government Mode when Python, pip packages, or third-party dependencies are blocked or slow to approve.

| Need | Best Fit | Why |
| --- | --- | --- |
| Fastest full experience | Python CLI | Best terminal UX, HTML reports, full packet workflow, richer commands, and normal package installation. |
| Locked-down Windows host | Government Mode | Uses built-in PowerShell and .NET only. No Python, pip, Typer, Rich, or external modules. |
| Recruiting or portfolio demo | Python CLI | `stigpilot demo` and `stigpilot chrome-demo` show the full product quickly. |
| Government workstation with strict third-party rules | Government Mode | Easier to review as a single local script. |
| Batch comparison across folders | Python CLI | Portfolio and batch workflows are Python-only. |
| One-off local triage packet | Either | Both can compare two STIG XCCDF files and produce local reports. |

## What Both Modes Do

Both paths are local helpers for STIG release change triage. They can:

- Parse STIG XCCDF/XML files
- Compare old and new STIG releases
- Detect added, removed, modified, and severity-increased controls
- Generate a Markdown change brief
- Generate a remediation backlog CSV
- Generate an evidence checklist
- Generate ticket-friendly local exports

Neither path scans systems, validates compliance, applies remediations, downloads official STIG content, or replaces official DISA tooling.

## Python CLI

Use this path when Python is approved:

```bash
python -m pip install -e ".[dev]"
stigpilot quickstart
stigpilot demo
```

For real STIG files:

```bash
stigpilot packet stigs/chrome-windows/v2r10/old.xml stigs/chrome-windows/v2r11/new.xml --out output/chrome-review
```

The Python CLI is the primary STIGPilot experience. It includes richer terminal output, HTML reports, Chrome demo support, batch portfolio comparison, config support, and the broadest test coverage.

## Government Mode

Use this path when the environment needs built-in Windows tooling only:

```powershell
.\tools\STIGPilot-Gov.ps1 -Command doctor
.\tools\STIGPilot-Gov.ps1 -Command packet -Old stigs\chrome-windows\v2r10\old.xml -New stigs\chrome-windows\v2r11\new.xml -OutDir output\chrome-gov
```

Or use the launcher:

```powershell
tools\STIGPilot.cmd -Command packet -Old stigs\chrome-windows\v2r10\old.xml -New stigs\chrome-windows\v2r11\new.xml -OutDir output\chrome-gov
```

Government Mode is intentionally smaller. It focuses on the core workflow: parse, compare, summarize, build a backlog, prepare evidence requests, and create local ticket exports.

## Practical Recommendation

Start with `stigpilot quickstart` on machines where Python is allowed. Start with `.\tools\STIGPilot-Gov.ps1 -Command doctor` on locked-down Windows machines. For input folder guidance, see [Where to Put STIG Files](where-to-put-stigs.md).

If both modes are available, use the Python CLI for the normal analyst workflow and keep Government Mode as the portable fallback for restricted hosts.
