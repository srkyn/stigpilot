[![STIGPilot banner](https://github.com/srkyn/stigpilot/raw/main/docs/assets/stigpilot-banner.png)](https://github.com/srkyn/stigpilot)

![STIGPilot demo](https://github.com/srkyn/stigpilot/raw/main/docs/assets/demos/stigpilot-demo.gif)


# STIGPilot

STIGPilot is a local Python CLI for the messy part that happens after a DISA STIG update drops: figuring out what changed, what matters, who needs to look at it, and what evidence or tickets should be refreshed.

[![Tests](https://github.com/srkyn/stigpilot/actions/workflows/tests.yml/badge.svg)](https://github.com/srkyn/stigpilot/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![PyPI](https://img.shields.io/pypi/v/stigpilot?style=flat-square&label=pypi)](https://pypi.org/project/stigpilot/)
![License](https://img.shields.io/badge/license-MIT-green)

## Why this exists

Official tools are still the authority for viewing, scanning, checklist work, and formal compliance. STIGPilot sits beside them as a helper for the part that usually turns into spreadsheets, side notes, and "who owns this?" conversations:

- What changed?
- What matters?
- What got more severe?
- What likely needs implementation work?
- What evidence needs to be refreshed?
- What tickets should be created?
- What should a manager know?

I built this after learning about STIGs and asking a practical question: if someone is responsible for applying these controls or comparing releases, what would actually make their day easier? The answer was not another viewer or scanner. It was a fast local helper that turns a dense XML release into a short brief, a backlog, and evidence requests people can act on.

## 30-second demo

```bash
git clone https://github.com/srkyn/stigpilot.git
cd stigpilot
python -m pip install -e ".[dev]"
stigpilot demo
```

Need the shortest path after install?

```bash
stigpilot quickstart
```

Generated files:

```text
output/demo/START_HERE.md
output/demo/change-brief.md
output/demo/change-brief.html
output/demo/changes.json
output/demo/manager-summary.md
output/demo/remediation-backlog.csv
output/demo/evidence-checklist.md
output/demo/jira-import.csv
output/demo/servicenow-import.csv
output/demo/github-issues.md
output/demo/remediation-drafts.md
```

Example terminal output:

```text
Demo Reports Generated
Start here           output/demo/START_HERE.md
Change brief          output/demo/change-brief.md
Manager summary       output/demo/manager-summary.md
Remediation backlog   output/demo/remediation-backlog.csv

Start here:
- Open output/demo/START_HERE.md
- Open output/demo/change-brief.md
- Open output/demo/manager-summary.md

STIGPilot Diff Summary
Total changes                     4
Added                             1
Removed                           1
Modified                          2
High-priority review              2
Evidence update likely            1
```

Change brief excerpt:

```text
4 control change(s) were detected. 3 change(s) are likely to require priority review,
implementation work, or evidence refresh. Prioritize high-severity additions or
severity increases, then review remediation text changes before reusing old tickets.
```

## Artifact preview

STIGPilot is built around reviewable outputs, not hidden scoring. A typical packet answers four questions:

| Question | Example from the sample packet |
|---|---|
| What changed? | `4 control change(s)` detected across the Chrome sample |
| What needs attention first? | `2` high-priority review items |
| Who should review it? | Endpoint/Windows Admin and Security/GRC Analyst owner groups |
| What can be handed off? | Backlog CSV, evidence checklist, manager summary, ticket imports, and review-only remediation drafts |

Useful sample artifacts:

- [Chrome change brief](examples/chrome_windows_output/change-brief.md)
- [Chrome HTML change brief](examples/chrome_windows_output/change-brief.html)
- [Chrome manager summary](examples/chrome_windows_output/manager-summary.md)
- [Chrome remediation backlog CSV](examples/chrome_windows_output/remediation-backlog.csv)
- [Chrome evidence checklist](examples/chrome_windows_output/evidence-checklist.md)
- [Portfolio comparison summary](examples/portfolio_output/portfolio-summary.md)

A complete pre-generated sample packet is available in [docs/sample-packet/](docs/sample-packet/) - open it directly without running anything to see what STIGPilot produces.

## Real-world Chrome demo

Google Chrome for Windows is the best first real-world scenario because it is familiar, endpoint-security relevant, and smaller than a full operating system STIG.

Run the built-in sanitized Chrome workflow:

```bash
stigpilot chrome-demo
```

![STIGPilot Chrome STIG demo](https://github.com/srkyn/stigpilot/raw/main/docs/assets/demos/stigpilot-chrome-demo.gif)


Generate a Chrome packet for only one team or impact category:

```bash
stigpilot chrome-demo --impact evidence_update_likely --owner "Endpoint/Windows Admin"
```

Generated files:

```text
output/chrome/change-brief.md
output/chrome/change-brief.html
output/chrome/changes.json
output/chrome/manager-summary.md
output/chrome/remediation-backlog.csv
output/chrome/evidence-checklist.md
output/chrome/jira-import.csv
output/chrome/servicenow-import.csv
output/chrome/github-issues.md
output/chrome/remediation-drafts.md
```

To run against official DoD Cyber Exchange Google Chrome Current Windows STIG V2R10 and V2R11 files, download the public ZIPs, extract the XCCDF XML files, and place them here:

```text
examples/chrome_windows_input/old.xml
examples/chrome_windows_input/new.xml
```

Then rerun:

```bash
stigpilot chrome-demo
```

## What STIGPilot is good at

- Release-to-release STIG change triage
- Folder-to-folder portfolio comparisons for multiple STIG updates
- Identifying severity increases and implementation-impacting changes
- Generating remediation backlog CSVs
- Preparing owner-focused evidence requests
- Creating manager summaries
- Exporting ticket-ready CSVs and GitHub issue drafts

## What STIGPilot is not

- Not official DISA tooling
- Not compliance validation
- Not a scanner
- Not auto-remediation
- Not a replacement for SCC, STIG Viewer, PowerSTIG, OpenRMF, or organizational compliance review

STIGPilot intentionally stops at the remediation-planning boundary. See [docs/remediation-boundary.md](docs/remediation-boundary.md) for why it generates reviewable work packets instead of applying system changes.

## When to use it

- A new Windows 11 STIG release drops and you need to know what changed.
- A vulnerability management analyst needs a backlog CSV.
- A GRC analyst needs an evidence checklist.
- A sysadmin team needs owner-focused remediation work.
- A manager needs a short update without reading hundreds of controls.

Need role-based commands? Start with [copy-paste workflows](docs/copy-paste-workflows.md).

## Install

From a clone:

```bash
git clone https://github.com/srkyn/stigpilot.git
cd stigpilot
python -m pip install -e .
```

Development dependencies:

```bash
python -m pip install -e ".[dev]"
```

With `pipx` from a local clone:

```bash
pipx install .
```

Fallback without the console script:

```bash
python -m stigpilot.cli --help
python -m stigpilot.cli demo
```

Windows note: if `stigpilot` is not recognized after install, your Python Scripts directory may not be on `PATH`. The `python -m stigpilot.cli ...` fallback works without changing `PATH`.

## Government Mode

Some government environments treat Python and pip packages as third-party software. STIGPilot includes a PowerShell-only fallback for restrictive Windows instances:

Not sure which path to use? See [Python CLI vs Government Mode](docs/python-vs-government-mode.md).

**No execution policy change required system-wide.** If PowerShell says scripts are
disabled, run this first - it only affects the current process and resets when you
close the window:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**Or use the included `.cmd` launcher** which handles this automatically:

```powershell
tools\STIGPilot.cmd -Command packet -Old old.xml -New new.xml -OutDir output\packet
```

**No git required.** If you cannot clone the repository, download
[`STIGPilot-Gov.ps1`](https://github.com/srkyn/stigpilot/raw/main/tools/STIGPilot-Gov.ps1)
and [`STIGPilot.cmd`](https://github.com/srkyn/stigpilot/raw/main/tools/STIGPilot.cmd)
directly. Place both files in the same folder. Run `STIGPilot.cmd` with your STIG
XML files as arguments.

```powershell
.\tools\STIGPilot-Gov.ps1 -Command doctor

.\tools\STIGPilot-Gov.ps1 -Command packet `
  -Old examples\sample_input\old.xml `
  -New examples\sample_input\new.xml `
  -OutDir output\gov

.\tools\STIGPilot-Gov.ps1 -Command inspect -OutDir output\gov
```

Generated files:

```text
output/gov/START_HERE.md
output/gov/change-brief.md
output/gov/remediation-backlog.csv
output/gov/changes.json
output/gov/evidence-checklist.md
output/gov/jira-import.csv
output/gov/servicenow-import.csv
output/gov/github-issues.md
```

This mode uses only built-in PowerShell/.NET XML, CSV, JSON, and file APIs. It is intentionally smaller than the Python CLI, but it preserves the core local workflow: parse, compare, summarize, produce a backlog, and prepare evidence requests. See [docs/government-mode.md](docs/government-mode.md).

Generate a focused Government Mode packet for one impact category or owner:

```powershell
.\tools\STIGPilot-Gov.ps1 -Command packet `
  -Old examples\sample_input\old.xml `
  -New examples\sample_input\new.xml `
  -OutDir output\gov-windows `
  -Impact high_priority_review `
  -Owner "Endpoint/Windows Admin"
```

## CLI usage

For role-based command recipes, see [copy-paste workflows](docs/copy-paste-workflows.md).

Health check:

```bash
stigpilot quickstart
stigpilot doctor
```

Parse a STIG:

```bash
stigpilot parse examples/sample_input/new.xml --csv output/controls.csv --json output/controls.json
```

Generate a brief:

```bash
stigpilot brief examples/sample_input/new.xml --out output/brief.md --severity high
```

Compare two STIG versions:

```bash
stigpilot diff examples/sample_input/old.xml examples/sample_input/new.xml --out output/change-brief.md --csv output/remediation-backlog.csv
```

Generate a complete local workflow packet from two STIG files:

```bash
stigpilot packet examples/sample_input/old.xml examples/sample_input/new.xml --out output/packet
stigpilot inspect-output output/packet
```

![STIGPilot packet generation - all output files in one command](https://github.com/srkyn/stigpilot/raw/main/docs/assets/demos/stigpilot-packet.gif)


Generate workflow exports:

```bash
stigpilot diff examples/sample_input/old.xml examples/sample_input/new.xml --out output/change-brief.md --csv output/remediation-backlog.csv --jira-csv output/jira-import.csv --servicenow-csv output/servicenow-import.csv --github-md output/github-issues.md --drafts-md output/remediation-drafts.md --json output/changes.json
```

Compare folders of old/new STIG XML files:

```bash
stigpilot batch examples/portfolio_input/old examples/portfolio_input/new --out output/portfolio
```

Generate a focused packet for one impact category or owner group:

```bash
stigpilot diff examples/sample_input/old.xml examples/sample_input/new.xml --out output/windows-high-priority.md --csv output/windows-high-priority.csv --impact high_priority_review --owner "Endpoint/Windows Admin"
```

Generate a manager-facing summary:

```bash
stigpilot manager examples/sample_input/old.xml examples/sample_input/new.xml --out output/manager-summary.md
```

Generate a self-contained HTML change brief:

```bash
stigpilot html examples/sample_input/old.xml examples/sample_input/new.xml --out output/change-brief.html
```

Generate ticket-ready export from one STIG:

```bash
stigpilot tickets examples/sample_input/new.xml --out output/tickets.csv --severity high
```

Generate an evidence checklist:

```bash
stigpilot evidence examples/sample_input/new.xml --out output/evidence-checklist.md
```

Generate review-only remediation drafts:

```bash
stigpilot drafts examples/sample_input/old.xml examples/sample_input/new.xml --out output/remediation-drafts.md
```

Show a terminal summary:

```bash
stigpilot summary examples/sample_input/new.xml
```

Write a configurable owner/tag mapping example:

```bash
stigpilot config-example --out stigpilot.toml
```

Use a local owner/tag mapping config:

```bash
stigpilot diff examples/sample_input/old.xml examples/sample_input/new.xml --out output/change-brief.md --csv output/remediation-backlog.csv --config stigpilot.toml
```

## Example outputs

Synthetic fixtures are included in `examples/sample_input/`. They are fake and sanitized.

Committed sample outputs in `examples/sample_output/`:

- `change-brief.md`
- `change-brief.html`
- `changes.json`
- `manager-summary.md`
- `remediation-backlog.csv`
- `evidence-checklist.md`
- `jira-import.csv`
- `servicenow-import.csv`
- `github-issues.md`
- `remediation-drafts.md`

One-command packet outputs are committed in `examples/packet_output/`.

Folder comparison sample outputs are committed in `examples/portfolio_output/`.

HTML report output is committed in `examples/html_output/`.

Machine-readable change exports include `schema_version: "1.0"` and are documented by [docs/schemas/changes.schema.json](docs/schemas/changes.schema.json).

Additional parsed-control and ticket-export examples:

- `controls.csv`
- `controls.json`
- `tickets.csv`

## Chrome for Windows official inputs

Official Google Chrome Current Windows STIG XML files are not vendored in this repository. The Chrome demo uses sanitized sample files unless you provide official XMLs under `examples/chrome_windows_input/`.

Suggested source ZIPs:

- `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R10_STIG.zip`
- `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R11_STIG.zip`

This keeps the project useful immediately while avoiding unclear redistribution of official STIG XML files.

## Impact rules

The classifier is intentionally transparent. There is no opaque AI dependency.

- New high severity control: `high_priority_review`
- Severity increased to high: `high_priority_review`
- Severity increased below high: `review_recommended`
- Meaningful fix text change: `implementation_change_likely`
- Meaningful check text change: `evidence_update_likely`
- Removed control: `review_recommended`
- Only title/metadata wording changed: `no_action_likely`
- CCI/reference changes: `review_recommended`

Text changes use a transparent similarity threshold of `0.86` plus configuration-language keywords. The goal is to separate wording-only churn from changes likely to affect implementation steps or evidence requests.

## Tags and ownership

Tags and suggested owners are keyword-based and explainable.

- Windows, GPO, Registry, Defender/AV: Endpoint/Windows Admin
- Linux, sshd, sudo, auditd, PAM: Linux Admin
- IAM, privileged access, authentication, lockout: IAM/Security Admin
- SQL, Oracle, PostgreSQL, MongoDB: Database Admin
- Firewall, router, switch, Cisco, Palo Alto: Network/Security Engineering
- Cloud, Azure, AWS, GCP, Entra: Cloud/IAM Admin
- Container, Kubernetes, Docker: Platform/Container Admin

Everything else defaults to Security/GRC Analyst.

Teams can extend mappings with a local TOML file:

```toml
[[owner_rules]]
owner = "Identity/IAM Team"
keywords = ["authentication", "privileged account"]

[tag_rules]
"Privileged Access" = ["privileged account", "sudoers"]
```

See [docs/configuration.md](docs/configuration.md) for owner routing examples, tag rules, and config validation notes.

## Limitations

- STIGPilot does not validate host compliance.
- STIGPilot does not replace formal review.
- STIGPilot does not download or scrape DISA content.
- STIGPilot does not auto-remediate.
- XML variants are handled best-effort; unusual vendor packaging may require parser improvements.
- Keyword tags and owner mapping are transparent but imperfect.

## Safe usage

Use STIGPilot only with files you are authorized to process. Do not publish sensitive evidence, system names, internal host data, credentials, classified information, or restricted organizational material. The included fixtures are synthetic.

## Roadmap

- Demo GIF in README showing terminal output
- Better HTML packet and portfolio report coverage
- More parser fixtures from official-but-user-supplied STIG variants
- More detailed review-only remediation draft formats
- Optional Streamlit dashboard after the CLI remains strong
- Additional Government Mode commands matching Python CLI parity

## What this demonstrates

- Built from a practical security-automation question: how can STIG comparison and follow-up work be made less painful for the people doing it?
- Defensive security product judgment
- XCCDF/XML parsing with namespace resilience
- STIG release change analysis
- Rule-based impact classification
- Ticket and evidence workflow design
- Testable Python CLI engineering

## Development

Run tests:

```bash
python -m pytest
```

Regenerate sample outputs:

```powershell
.\tools\regenerate-examples.ps1
```

The script refreshes the Python CLI examples, packet output, Chrome sample
packet, portfolio packet, docs sample packet, HTML report, and Government Mode
output.
