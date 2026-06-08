<#
.SYNOPSIS
Regenerate committed STIGPilot example outputs.

.DESCRIPTION
Runs the Python CLI and the PowerShell Government Mode wrapper against the
synthetic fixtures in examples/. Use this before releases when report formats,
exports, or sample data change.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $RepoRoot

try {
    function Invoke-STIGPilot {
        param(
            [Parameter(Mandatory = $true)]
            [string[]]$Arguments
        )

        Write-Host "python -m stigpilot.cli $($Arguments -join ' ')" -ForegroundColor Cyan
        & python -m stigpilot.cli @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed: python -m stigpilot.cli $($Arguments -join ' ')"
        }
    }

    $old = "examples/sample_input/old.xml"
    $new = "examples/sample_input/new.xml"

    Invoke-STIGPilot @("diff", $old, $new,
        "--out", "examples/sample_output/change-brief.md",
        "--csv", "examples/sample_output/remediation-backlog.csv",
        "--jira-csv", "examples/sample_output/jira-import.csv",
        "--servicenow-csv", "examples/sample_output/servicenow-import.csv",
        "--github-md", "examples/sample_output/github-issues.md",
        "--drafts-md", "examples/sample_output/remediation-drafts.md",
        "--json", "examples/sample_output/changes.json")

    Invoke-STIGPilot @("html", $old, $new, "--out", "examples/sample_output/change-brief.html")
    Invoke-STIGPilot @("manager", $old, $new, "--out", "examples/sample_output/manager-summary.md")
    Invoke-STIGPilot @("parse", $new, "--csv", "examples/sample_output/controls.csv", "--json", "examples/sample_output/controls.json")
    Invoke-STIGPilot @("brief", $new, "--out", "examples/sample_output/brief.md")
    Invoke-STIGPilot @("tickets", $new, "--out", "examples/sample_output/tickets.csv")
    Invoke-STIGPilot @("evidence", $new, "--out", "examples/sample_output/evidence-checklist.md")

    Invoke-STIGPilot @("packet", $old, $new, "--out", "examples/packet_output")
    Invoke-STIGPilot @("packet", $old, $new, "--out", "docs/sample-packet")
    Invoke-STIGPilot @("html", $old, $new, "--out", "examples/html_output/change-brief.html")
    Invoke-STIGPilot @("batch", "examples/portfolio_input/old", "examples/portfolio_input/new", "--out", "examples/portfolio_output")
    Invoke-STIGPilot @("chrome-demo", "--out", "examples/chrome_windows_output", "--input-dir", "examples/chrome_windows_input")

    Write-Host "powershell -File tools/STIGPilot-Gov.ps1 -Command packet ..." -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File "tools/STIGPilot-Gov.ps1" `
        -Command packet `
        -Old $old `
        -New $new `
        -OutDir "examples/government_mode_output"
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: tools/STIGPilot-Gov.ps1 -Command packet"
    }

    Write-Host ""
    Write-Host "Example outputs regenerated." -ForegroundColor Green
    Write-Host "Review git diff before committing generated files." -ForegroundColor Green
}
finally {
    Pop-Location
}
