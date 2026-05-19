<#
STIGPilot Government Mode

PowerShell-only STIG change triage for restrictive Windows environments where
Python and third-party packages may not be approved. This script uses only
built-in PowerShell/.NET XML, CSV, JSON, and file APIs.

Examples:
  .\tools\STIGPilot-Gov.ps1 -Command packet -Old examples\sample_input\old.xml -New examples\sample_input\new.xml -OutDir output\gov
  .\tools\STIGPilot-Gov.ps1 -Command packet -Old examples\sample_input\old.xml -New examples\sample_input\new.xml -OutDir output\gov-windows -Impact high_priority_review -Owner "Endpoint/Windows Admin"
  .\tools\STIGPilot-Gov.ps1 -Command parse -Input examples\sample_input\new.xml -Csv output\gov\controls.csv -Json output\gov\controls.json
  .\tools\STIGPilot-Gov.ps1 -Command evidence -Input examples\sample_input\new.xml -OutDir output\gov
#>

[CmdletBinding()]
param(
    [ValidateSet("help", "parse", "diff", "evidence", "packet")]
    [string]$Command = "help",

    [Alias("Input")]
    [string]$InputFile,
    [string]$Old,
    [string]$New,
    [string]$OutDir = "output\gov",
    [string]$Csv,
    [string]$Json,
    [string]$Markdown,
    [string]$Impact,
    [string]$Owner
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Write-GovHelp {
    Write-Host ""
    Write-Host "STIGPilot Government Mode" -ForegroundColor Cyan
    Write-Host "PowerShell-only STIG parse, diff, backlog, and evidence exports."
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  help      Show this help"
    Write-Host "  parse     Parse one XCCDF/XML file to CSV and/or JSON"
    Write-Host "  diff      Compare old/new XCCDF/XML files and write a Markdown brief/backlog CSV"
    Write-Host "  evidence  Generate an evidence checklist from one XCCDF/XML file"
    Write-Host "  packet    Generate change brief, backlog CSV, ticket exports, changes JSON, and evidence checklist"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\tools\STIGPilot-Gov.ps1 -Command packet -Old examples\sample_input\old.xml -New examples\sample_input\new.xml -OutDir output\gov"
    Write-Host "  .\tools\STIGPilot-Gov.ps1 -Command packet -Old examples\sample_input\old.xml -New examples\sample_input\new.xml -OutDir output\gov-windows -Impact high_priority_review -Owner `"Endpoint/Windows Admin`""
    Write-Host "  .\tools\STIGPilot-Gov.ps1 -Command parse -Input examples\sample_input\new.xml -Csv output\gov\controls.csv -Json output\gov\controls.json"
    Write-Host ""
    Write-Host "Notes:"
    Write-Host "  - Uses only built-in PowerShell/.NET features."
    Write-Host "  - Does not scan systems, validate compliance, or replace official DISA tooling."
    Write-Host "  - Intended as a lightweight fallback for local change triage and evidence planning."
    Write-Host ""
}

function Test-ImpactFilter {
    param([AllowNull()][string]$ImpactValue)
    if (-not $ImpactValue) {
        return
    }
    $allowed = @(
        "high_priority_review",
        "implementation_change_likely",
        "evidence_update_likely",
        "review_recommended",
        "no_action_likely"
    )
    if ($ImpactValue -notin $allowed) {
        throw "-Impact must be one of: $($allowed -join ', ')"
    }
}

function Select-FilteredChanges {
    param($Changes)
    Test-ImpactFilter $Impact
    $filtered = @($Changes)
    if ($Impact) {
        $filtered = @($filtered | Where-Object { $_.impact -eq $Impact })
    }
    if ($Owner) {
        $filtered = @($filtered | Where-Object { $_.owner -eq $Owner })
    }
    return $filtered
}

function Resolve-ExistingPath {
    param([Parameter(Mandatory = $true)][string]$PathValue)
    if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
        throw "File not found: $PathValue"
    }
    return (Resolve-Path -LiteralPath $PathValue).Path
}

function Ensure-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$PathValue)
    $parent = Split-Path -Parent $PathValue
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$PathValue)
    if (-not (Test-Path -LiteralPath $PathValue)) {
        New-Item -ItemType Directory -Path $PathValue -Force | Out-Null
    }
}

function Get-AttributeValue {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($Node.Attributes -and $Node.Attributes[$Name]) {
        return [string]$Node.Attributes[$Name].Value
    }
    return ""
}

function Normalize-Text {
    param([AllowNull()][string]$Text)
    if (-not $Text) {
        return ""
    }
    return (($Text -replace "\s+", " ").Trim())
}

function Get-FirstText {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)][string]$XPath
    )
    $match = $Node.SelectSingleNode($XPath)
    if ($null -eq $match) {
        return ""
    }
    return Normalize-Text $match.InnerText
}

function Get-Texts {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)][string]$XPath
    )
    $values = @()
    foreach ($match in $Node.SelectNodes($XPath)) {
        $text = Normalize-Text $match.InnerText
        if ($text) {
            $values += $text
        }
    }
    return @($values | Select-Object -Unique)
}

function Get-StigDocument {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    $resolved = Resolve-ExistingPath $PathValue
    $xml = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $false
    try {
        $xml.Load($resolved)
    }
    catch {
        throw "Invalid XML in $PathValue. $($_.Exception.Message)"
    }

    $benchmark = $xml.SelectSingleNode("//*[local-name()='Benchmark']")
    if ($null -eq $benchmark) {
        throw "No XCCDF Benchmark element found in $PathValue."
    }

    $stigId = Get-AttributeValue $benchmark "id"
    $docTitle = Get-FirstText -Node $benchmark -XPath "./*[local-name()='title']"
    $docVersion = Get-FirstText -Node $benchmark -XPath "./*[local-name()='version']"
    $docRelease = Get-FirstText -Node $benchmark -XPath ".//*[local-name()='plain-text']"
    $controls = @()

    foreach ($group in $benchmark.SelectNodes(".//*[local-name()='Group']")) {
        $groupId = Get-AttributeValue $group "id"
        $vulnId = ""
        if ($groupId -match "V-\d+") {
            $vulnId = $Matches[0]
        }

        foreach ($rule in $group.SelectNodes("./*[local-name()='Rule']")) {
            $ruleId = Get-AttributeValue $rule "id"
            $severity = (Get-AttributeValue $rule "severity").ToLowerInvariant()
            $identRefs = Get-Texts -Node $rule -XPath ".//*[local-name()='ident']"
            $cciRefs = @($identRefs | Where-Object { $_ -match "^CCI-\d+" })

            $references = @()
            foreach ($ref in $rule.SelectNodes(".//*[local-name()='reference']")) {
                $refText = Normalize-Text $ref.InnerText
                $href = Get-AttributeValue $ref "href"
                if ($refText) {
                    $references += $refText
                }
                elseif ($href) {
                    $references += $href
                }
            }

            $controlText = @(
                Get-FirstText -Node $rule -XPath "./*[local-name()='title']"
                Get-FirstText -Node $rule -XPath ".//*[local-name()='check-content']"
                Get-FirstText -Node $rule -XPath ".//*[local-name()='fixtext']"
            ) -join " "

            $control = [PSCustomObject]@{
                vuln_id    = $vulnId
                rule_id    = $ruleId
                group_id   = $groupId
                stig_id    = $stigId
                title      = Get-FirstText -Node $rule -XPath "./*[local-name()='title']"
                severity   = $severity
                check_text = Get-FirstText -Node $rule -XPath ".//*[local-name()='check-content']"
                fix_text   = Get-FirstText -Node $rule -XPath ".//*[local-name()='fixtext']"
                cci_refs   = @($cciRefs | Select-Object -Unique)
                references = @($references | Select-Object -Unique)
                raw_id     = $ruleId
                owner      = Get-SuggestedOwner $controlText
                tags       = @(Get-Tags $controlText)
            }
            $controls += $control
        }
    }

    if ($controls.Count -eq 0) {
        throw "No Rule controls found in $PathValue. Confirm this is an XCCDF STIG XML file."
    }

    return [PSCustomObject]@{
        title       = $docTitle
        version     = $docVersion
        release     = $docRelease
        source_file = $resolved
        controls    = $controls
    }
}

function Get-ComparisonKey {
    param([Parameter(Mandatory = $true)]$Control)
    if ($Control.vuln_id) {
        return "vuln:$($Control.vuln_id)"
    }
    if ($Control.rule_id) {
        $rule = ($Control.rule_id -replace "_rule$", "" -replace "_r\d+$", "")
        return "rule:$rule"
    }
    if ($Control.group_id) {
        return "group:$($Control.group_id)"
    }
    return "raw:$($Control.raw_id)"
}

function Join-List {
    param([AllowNull()]$Values)
    if ($null -eq $Values) {
        return ""
    }
    return (@($Values) | Sort-Object) -join "; "
}

function Get-ChangedFields {
    param($OldControl, $NewControl)
    $fields = @()
    foreach ($field in @("title", "severity", "check_text", "fix_text")) {
        if ((Normalize-Text $OldControl.$field) -ne (Normalize-Text $NewControl.$field)) {
            $fields += $field
        }
    }
    if ((Join-List $OldControl.cci_refs) -ne (Join-List $NewControl.cci_refs)) {
        $fields += "cci_refs"
    }
    if ((Join-List $OldControl.references) -ne (Join-List $NewControl.references)) {
        $fields += "references"
    }
    return $fields
}

function Get-SeverityRank {
    param([AllowNull()][string]$Severity)
    switch (($Severity | ForEach-Object { "$_".ToLowerInvariant() })) {
        "high" { return 3 }
        "medium" { return 2 }
        "low" { return 1 }
        default { return 0 }
    }
}

function Get-ImpactLabel {
    param([Parameter(Mandatory = $true)][string]$Impact)
    switch ($Impact) {
        "high_priority_review" { "High-priority review" }
        "implementation_change_likely" { "Implementation change likely" }
        "evidence_update_likely" { "Evidence update likely" }
        "review_recommended" { "Review recommended" }
        "no_action_likely" { "No action likely" }
        default { $Impact }
    }
}

function Get-Impact {
    param(
        [Parameter(Mandatory = $true)][string]$ChangeType,
        [string[]]$ChangedFields = @(),
        $OldControl,
        $NewControl
    )

    $current = if ($null -ne $NewControl) { $NewControl } else { $OldControl }
    $severity = if ($null -ne $current) { "$($current.severity)".ToLowerInvariant() } else { "" }

    if ($ChangeType -eq "added" -and $severity -eq "high") {
        return @("high_priority_review", "A new high-severity control was added, so it should be reviewed before lower-risk backlog items.")
    }
    if ($ChangedFields -contains "severity") {
        if ((Get-SeverityRank $NewControl.severity) -gt (Get-SeverityRank $OldControl.severity)) {
            return @("high_priority_review", "The severity increased, so the control should be reviewed before reusing old risk notes, tickets, or evidence.")
        }
        return @("review_recommended", "The severity changed and should be reviewed for triage and reporting impact.")
    }
    if ($ChangedFields -contains "fix_text") {
        return @("implementation_change_likely", "The remediation text changed enough that old implementation notes or existing tickets should be reviewed before reuse.")
    }
    if ($ChangedFields -contains "check_text") {
        return @("evidence_update_likely", "The validation steps changed enough that evidence requests may need to be refreshed.")
    }
    if (($ChangedFields -contains "cci_refs") -or ($ChangedFields -contains "references")) {
        return @("review_recommended", "Reference or CCI mappings changed, so traceability should be reviewed without assuming implementation work.")
    }
    if ($ChangeType -eq "removed") {
        return @("review_recommended", "The control was removed from the newer file; review whether open tickets or evidence requests can be closed or retired.")
    }
    if ($ChangeType -eq "added") {
        return @("review_recommended", "A new control was added and should be triaged for ownership, ticketing, and evidence needs.")
    }
    return @("no_action_likely", "Only wording or metadata appears to have changed; keep awareness but avoid creating noisy remediation work.")
}

function Compare-StigDocuments {
    param($OldDoc, $NewDoc)

    $oldMap = @{}
    $newMap = @{}
    $duplicateKeys = @()

    foreach ($control in $OldDoc.controls) {
        $key = Get-ComparisonKey $control
        if ($oldMap.ContainsKey($key)) {
            $duplicateKeys += $key
        }
        else {
            $oldMap[$key] = $control
        }
    }
    foreach ($control in $NewDoc.controls) {
        $key = Get-ComparisonKey $control
        if ($newMap.ContainsKey($key)) {
            $duplicateKeys += $key
        }
        else {
            $newMap[$key] = $control
        }
    }
    if ($duplicateKeys.Count -gt 0) {
        Write-Warning ("Duplicate comparison keys detected: " + (($duplicateKeys | Select-Object -Unique) -join ", "))
    }

    $changes = @()
    foreach ($key in $oldMap.Keys) {
        if (-not $newMap.ContainsKey($key)) {
            $impact = Get-Impact -ChangeType "removed" -OldControl $oldMap[$key]
            $changes += New-ChangeObject "removed" $oldMap[$key] $null @() $impact[0] $impact[1]
        }
    }
    foreach ($key in $newMap.Keys) {
        if (-not $oldMap.ContainsKey($key)) {
            $impact = Get-Impact -ChangeType "added" -NewControl $newMap[$key]
            $changes += New-ChangeObject "added" $null $newMap[$key] @() $impact[0] $impact[1]
        }
        else {
            $fields = @(Get-ChangedFields $oldMap[$key] $newMap[$key])
            if ($fields.Count -gt 0) {
                $changeType = "modified"
                if ($fields -contains "severity") {
                    if ((Get-SeverityRank $newMap[$key].severity) -gt (Get-SeverityRank $oldMap[$key].severity)) {
                        $changeType = "severity_increased"
                    }
                    elseif ((Get-SeverityRank $newMap[$key].severity) -lt (Get-SeverityRank $oldMap[$key].severity)) {
                        $changeType = "severity_decreased"
                    }
                    else {
                        $changeType = "severity_changed"
                    }
                }
                elseif (($fields -contains "references") -or ($fields -contains "cci_refs")) {
                    $changeType = "reference_changed"
                }
                elseif ($fields.Count -eq 1 -and $fields -contains "title") {
                    $changeType = "metadata_only_change"
                }
                $impact = Get-Impact -ChangeType $changeType -ChangedFields $fields -OldControl $oldMap[$key] -NewControl $newMap[$key]
                $changes += New-ChangeObject $changeType $oldMap[$key] $newMap[$key] $fields $impact[0] $impact[1]
            }
        }
    }
    return @($changes | Sort-Object @{ Expression = { Get-ImpactSort $_.impact } }, @{ Expression = { $_.severity } }, vuln_id, rule_id)
}

function Get-ImpactSort {
    param([string]$Impact)
    switch ($Impact) {
        "high_priority_review" { return 0 }
        "implementation_change_likely" { return 1 }
        "evidence_update_likely" { return 2 }
        "review_recommended" { return 3 }
        default { return 4 }
    }
}

function New-ChangeObject {
    param(
        [string]$ChangeType,
        $OldControl,
        $NewControl,
        [string[]]$ChangedFields,
        [string]$Impact,
        [string]$Reason
    )
    $current = if ($null -ne $NewControl) { $NewControl } else { $OldControl }
    return [PSCustomObject]@{
        change_type    = $ChangeType
        vuln_id        = if ($current) { $current.vuln_id } else { "" }
        rule_id        = if ($current) { $current.rule_id } else { "" }
        title          = if ($current) { $current.title } else { "" }
        severity       = if ($current) { $current.severity } else { "" }
        impact         = $Impact
        impact_label   = Get-ImpactLabel $Impact
        reason         = $Reason
        changed_fields = @($ChangedFields)
        owner          = if ($current) { $current.owner } else { "Security/GRC Analyst" }
        tags           = if ($current) { @($current.tags) } else { @() }
        check_text     = if ($current) { $current.check_text } else { "" }
        fix_text       = if ($current) { $current.fix_text } else { "" }
    }
}

function Get-SuggestedOwner {
    param([AllowNull()][string]$Text)
    $value = "$Text".ToLowerInvariant()
    if ($value -match "windows|registry|gpo|group policy|defender|audit policy|local security policy|chrome|browser") {
        return "Endpoint/Windows Admin"
    }
    if ($value -match "linux|sshd|sudo|auditd|pam|/etc/|systemctl") {
        return "Linux Admin"
    }
    if ($value -match "database|sql|oracle|postgresql|mongodb|mysql") {
        return "Database Admin"
    }
    if ($value -match "network|router|firewall|switch|cisco|palo alto|vpn") {
        return "Network/Security Engineering"
    }
    if ($value -match "cloud|aws|azure|gcp|iam role|kubernetes|container") {
        return "Cloud/Security Engineering"
    }
    return "Security/GRC Analyst"
}

function Get-Tags {
    param([AllowNull()][string]$Text)
    $value = "$Text".ToLowerInvariant()
    $tags = @()
    $rules = [ordered]@{
        "Windows" = "windows|local security policy"
        "GPO" = "gpo|group policy"
        "Registry" = "registry|regedit|hkey_"
        "Defender/AV" = "defender|antivirus|anti-virus|malware"
        "Linux" = "linux|/etc/|systemctl|sshd|sudo|pam|auditd"
        "IAM" = "identity|account|user|group|privilege|role|iam"
        "Privileged Access" = "admin|administrator|root|privileged|sudo"
        "Password Policy" = "password|lockout|credential"
        "Audit Logging" = "audit|logging|event log|syslog|forwarding"
        "Remote Access" = "remote|ssh|rdp|vpn"
        "Encryption" = "tls|ssl|encryption|certificate|cryptographic"
        "Database" = "database|sql|oracle|postgresql|mongodb|mysql"
        "Network Security" = "router|firewall|switch|cisco|palo alto|network"
        "Cloud" = "aws|azure|gcp|cloud"
        "Container/Kubernetes" = "kubernetes|container|docker|pod"
        "Browser Security" = "chrome|browser|safe browsing|extension|cookies"
    }
    foreach ($name in $rules.Keys) {
        if ($value -match $rules[$name]) {
            $tags += $name
        }
    }
    if ($tags.Count -eq 0) {
        $tags += "Security Review"
    }
    return @($tags | Select-Object -Unique)
}

function Get-Summary {
    param([string]$Text, [int]$Max = 180)
    $clean = Normalize-Text $Text
    if ($clean.Length -le $Max) {
        return $clean
    }
    return $clean.Substring(0, $Max - 3) + "..."
}

function Get-EvidenceRequests {
    param($Control)
    $text = ("$($Control.title) $($Control.check_text) $($Control.fix_text)").ToLowerInvariant()
    $items = @("Screenshot or export of the relevant setting", "Date/time of validation", "System or asset name", "Reviewer notes")
    if ($text -match "gpo|group policy|windows|registry|chrome|browser") {
        $items += "GPO, registry, browser policy, or configuration export"
    }
    if ($text -match "linux|sshd|sudo|auditd|pam|/etc/") {
        $items += "Command output and relevant configuration file excerpt"
    }
    if ($text -match "firewall|router|switch|network|vpn") {
        $items += "Device configuration excerpt or management console export"
    }
    if ($text -match "database|sql|oracle|postgresql|mongodb") {
        $items += "Database configuration query output or admin console export"
    }
    return @($items | Select-Object -Unique)
}

function Write-ControlsCsv {
    param($Document, [string]$PathValue)
    Ensure-ParentDirectory $PathValue
    $Document.controls | ForEach-Object {
        [PSCustomObject]@{
            "Vuln ID" = $_.vuln_id
            "Rule ID" = $_.rule_id
            "Group ID" = $_.group_id
            "STIG ID" = $_.stig_id
            "Title" = $_.title
            "Severity" = $_.severity
            "Check Text" = $_.check_text
            "Fix Text" = $_.fix_text
            "CCI References" = Join-List $_.cci_refs
            "References" = Join-List $_.references
            "Tags" = Join-List $_.tags
            "Raw ID" = $_.raw_id
        }
    } | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $PathValue
}

function Write-ControlsJson {
    param($Document, [string]$PathValue)
    Ensure-ParentDirectory $PathValue
    $Document | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $PathValue
}

function Write-BacklogCsv {
    param($Changes, [string]$PathValue)
    Ensure-ParentDirectory $PathValue
    $Changes | ForEach-Object {
        [PSCustomObject]@{
            "Title" = $_.title
            "Vuln ID" = $_.vuln_id
            "Rule ID" = $_.rule_id
            "Severity" = $_.severity
            "Change Type" = $_.change_type
            "Impact" = $_.impact_label
            "Suggested Owner" = $_.owner
            "Tags" = Join-List $_.tags
            "Why It Matters" = $_.reason
            "Check Summary" = Get-Summary $_.check_text
            "Fix Summary" = Get-Summary $_.fix_text
            "Evidence Needed" = (Get-EvidenceRequests $_) -join "; "
            "Status" = "Not Started"
            "Notes" = ""
        }
    } | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $PathValue
}

function Get-TicketPriority {
    param($Change)
    if ($Change.impact -eq "high_priority_review") {
        return "High"
    }
    if ($Change.impact -eq "implementation_change_likely") {
        return "Medium"
    }
    if ($Change.impact -eq "evidence_update_likely") {
        return "Medium"
    }
    return "Low"
}

function Get-TicketDescription {
    param($Change)
    $evidence = (Get-EvidenceRequests $Change) -join "; "
    return @(
        "STIGPilot Government Mode triage item"
        ""
        "Control: $($Change.vuln_id) / $($Change.rule_id)"
        "Title: $($Change.title)"
        "Severity: $($Change.severity)"
        "Change type: $($Change.change_type)"
        "Impact: $($Change.impact_label)"
        "Suggested owner: $($Change.owner)"
        "Tags: $(Join-List $Change.tags)"
        ""
        "Why it matters: $($Change.reason)"
        ""
        "Check summary: $(Get-Summary $Change.check_text 260)"
        "Fix summary: $(Get-Summary $Change.fix_text 260)"
        ""
        "Evidence needed: $evidence"
        ""
        "Note: This is a local workflow helper export. It does not scan systems or validate compliance."
    ) -join [Environment]::NewLine
}

function Write-JiraCsv {
    param($Changes, [string]$PathValue)
    Ensure-ParentDirectory $PathValue
    $Changes | ForEach-Object {
        [PSCustomObject]@{
            "Summary" = "$($_.change_type): $($_.vuln_id) - $($_.title)"
            "Issue Type" = "Task"
            "Priority" = Get-TicketPriority $_
            "Labels" = (@("stigpilot", "government-mode", $_.impact) + @($_.tags | ForEach-Object { "$_".ToLowerInvariant() -replace "[^a-z0-9]+", "-" })) -join ","
            "Description" = Get-TicketDescription $_
        }
    } | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $PathValue
}

function Write-ServiceNowCsv {
    param($Changes, [string]$PathValue)
    Ensure-ParentDirectory $PathValue
    $Changes | ForEach-Object {
        [PSCustomObject]@{
            "short_description" = "$($_.change_type): $($_.vuln_id) - $($_.title)"
            "description" = Get-TicketDescription $_
            "assignment_group" = $_.owner
            "priority" = Get-TicketPriority $_
            "u_stig_vuln_id" = $_.vuln_id
            "u_stig_rule_id" = $_.rule_id
            "u_stig_impact" = $_.impact_label
            "u_stig_tags" = Join-List $_.tags
        }
    } | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $PathValue
}

function Write-GitHubIssuesMarkdown {
    param($Changes, [string]$PathValue)
    Ensure-ParentDirectory $PathValue
    $lines = @()
    $lines += "# STIGPilot Government Mode GitHub Issue Drafts"
    $lines += ""
    $lines += "Copy these drafts into GitHub Issues if that workflow fits your environment. These are triage tasks, not compliance validation claims."
    $lines += ""
    foreach ($change in $Changes) {
        $labels = (@("stigpilot", "government-mode", $change.impact) + @($change.tags | ForEach-Object { "$_".ToLowerInvariant() -replace "[^a-z0-9]+", "-" })) -join ", "
        $lines += "## $($change.change_type): $($change.vuln_id) - $($change.title)"
        $lines += ""
        $lines += 'Labels: `' + $labels + '`'
        $lines += ""
        $lines += "### Context"
        $lines += ""
        $lines += "- Severity: $($change.severity)"
        $lines += "- Rule ID: $($change.rule_id)"
        $lines += "- Impact: $($change.impact_label)"
        $lines += "- Suggested owner: $($change.owner)"
        $lines += "- Why it matters: $($change.reason)"
        $lines += ""
        $lines += "### Acceptance Criteria"
        $lines += ""
        $lines += "- [ ] Review the changed STIG guidance."
        $lines += "- [ ] Confirm whether implementation work, evidence refresh, or ticket closure is needed."
        $lines += "- [ ] Attach evidence or notes from the responsible owner."
        $lines += "- [ ] Document the final triage decision."
        $lines += ""
        $lines += "### Evidence Checklist"
        $lines += ""
        foreach ($item in (Get-EvidenceRequests $change)) {
            $lines += "- [ ] $item"
        }
        $lines += ""
        $lines += "### Notes"
        $lines += ""
        $lines += '- Generated by `tools/STIGPilot-Gov.ps1`.'
        $lines += "- This issue draft supports local triage and does not validate compliance."
        $lines += ""
    }
    ($lines -join [Environment]::NewLine).TrimEnd() | Set-Content -Encoding UTF8 -Path $PathValue
}

function Write-ChangesJson {
    param($OldDoc, $NewDoc, $Changes, [string]$PathValue)
    Ensure-ParentDirectory $PathValue
    $payload = [PSCustomObject]@{
        mode = "government_powershell"
        generated_by = "tools/STIGPilot-Gov.ps1"
        source = [PSCustomObject]@{
            old_file = $OldDoc.source_file
            new_file = $NewDoc.source_file
            old_title = $OldDoc.title
            new_title = $NewDoc.title
            old_control_count = $OldDoc.controls.Count
            new_control_count = $NewDoc.controls.Count
        }
        summary = Get-ChangeCounts $Changes
        changes = $Changes
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $PathValue
}

function Get-ChangeCounts {
    param($Changes)
    return [PSCustomObject]@{
        total = @($Changes).Count
        added = @($Changes | Where-Object { $_.change_type -eq "added" }).Count
        removed = @($Changes | Where-Object { $_.change_type -eq "removed" }).Count
        modified = @($Changes | Where-Object { $_.change_type -notin @("added", "removed") }).Count
        severity_increased = @($Changes | Where-Object { $_.change_type -eq "severity_increased" }).Count
        high_priority_review = @($Changes | Where-Object { $_.impact -eq "high_priority_review" }).Count
        implementation_change_likely = @($Changes | Where-Object { $_.impact -eq "implementation_change_likely" }).Count
        evidence_update_likely = @($Changes | Where-Object { $_.impact -eq "evidence_update_likely" }).Count
    }
}

function Write-ChangeBrief {
    param($OldDoc, $NewDoc, $Changes, [string]$PathValue)
    Ensure-ParentDirectory $PathValue
    $counts = Get-ChangeCounts $Changes
    $ownerGroups = $Changes | Group-Object owner | Sort-Object Count -Descending
    $top = @($Changes | Select-Object -First 10)
    $topOwner = "No owner group"
    if (@($ownerGroups).Count -gt 0) {
        $topOwner = (@($ownerGroups)[0]).Name
    }

    $lines = @()
    $lines += "# STIGPilot Government Mode Change Brief"
    $lines += ""
    $lines += "## Executive Summary"
    $lines += ""
    $lines += "$($counts.total) control change(s) were detected between the supplied XCCDF files. $($counts.high_priority_review) change(s) need high-priority review, $($counts.implementation_change_likely) likely require implementation review, and $($counts.evidence_update_likely) likely require refreshed evidence. The most affected owner group is $topOwner. Use this as local triage support; it does not scan systems or validate compliance."
    $lines += ""
    $lines += "## Source Files"
    $lines += ""
    $lines += "- Old source: ``$(Split-Path -Leaf $OldDoc.source_file)``"
    $lines += "- New source: ``$(Split-Path -Leaf $NewDoc.source_file)``"
    $lines += "- Old controls: $($OldDoc.controls.Count)"
    $lines += "- New controls: $($NewDoc.controls.Count)"
    $lines += ""
    $lines += "## At-a-Glance"
    $lines += ""
    $lines += "| Metric | Count |"
    $lines += "| --- | ---: |"
    $lines += "| Added controls | $($counts.added) |"
    $lines += "| Removed controls | $($counts.removed) |"
    $lines += "| Modified controls | $($counts.modified) |"
    $lines += "| Severity increases | $($counts.severity_increased) |"
    $lines += "| High-priority review | $($counts.high_priority_review) |"
    $lines += "| Implementation change likely | $($counts.implementation_change_likely) |"
    $lines += "| Evidence update likely | $($counts.evidence_update_likely) |"
    $lines += ""
    $lines += "## Priority Actions"
    $lines += ""
    if ($top.Count -eq 0) {
        $lines += "- No changes detected."
    }
    else {
        $index = 1
        foreach ($change in $top) {
            $lines += "$index. **$($change.vuln_id) - $($change.title)**"
            $lines += "   - Impact: $($change.impact_label)"
            $lines += "   - Owner: $($change.owner)"
            $lines += "   - Why it matters: $($change.reason)"
            $index += 1
        }
    }
    $lines += ""
    $lines += "## Owner Impact"
    $lines += ""
    $lines += "| Owner | Changes | High Priority | Implementation Likely | Evidence Updates |"
    $lines += "| --- | ---: | ---: | ---: | ---: |"
    foreach ($group in $ownerGroups) {
        $groupChanges = @($group.Group)
        $lines += "| $($group.Name) | $($group.Count) | $(@($groupChanges | Where-Object { $_.impact -eq 'high_priority_review' }).Count) | $(@($groupChanges | Where-Object { $_.impact -eq 'implementation_change_likely' }).Count) | $(@($groupChanges | Where-Object { $_.impact -eq 'evidence_update_likely' }).Count) |"
    }
    $lines += ""
    $lines += "## Detailed Changes"
    $lines += ""
    $lines += "| Change Type | Impact | Severity | Vuln ID | Rule ID | Title | Owner | Why it matters |"
    $lines += "| --- | --- | --- | --- | --- | --- | --- | --- |"
    foreach ($change in $Changes) {
        $title = "$($change.title)" -replace "\|", "\|"
        $reason = "$($change.reason)" -replace "\|", "\|"
        $lines += "| $($change.change_type) | $($change.impact_label) | $($change.severity) | $($change.vuln_id) | $($change.rule_id) | $title | $($change.owner) | $reason |"
    }
    ($lines -join [Environment]::NewLine).TrimEnd() | Set-Content -Encoding UTF8 -Path $PathValue
}

function Write-EvidenceChecklist {
    param($Controls, [string]$PathValue)
    Ensure-ParentDirectory $PathValue
    $lines = @()
    $lines += "# STIGPilot Government Mode Evidence Checklist"
    $lines += ""
    $lines += "Use this checklist to prepare evidence requests. This helper does not validate compliance."
    $lines += ""

    foreach ($group in ($Controls | Group-Object owner | Sort-Object Name)) {
        $lines += "## $($group.Name)"
        $lines += ""
        foreach ($control in $group.Group) {
            $controlId = if ($control.vuln_id) { $control.vuln_id } else { $control.rule_id }
            $lines += "### $controlId - $($control.title)"
            $lines += ""
            $lines += "- Severity: $($control.severity)"
            $lines += "- Rule ID: $($control.rule_id)"
            $lines += "- Tags: $(Join-List $control.tags)"
            $lines += ""
            $lines += "Validation metadata:"
            $lines += ""
            $lines += "- Asset/System:"
            $lines += "- Environment:"
            $lines += "- Validated by:"
            $lines += "- Date:"
            $lines += "- Notes:"
            $lines += ""
            $lines += "Evidence requests:"
            foreach ($item in (Get-EvidenceRequests $control)) {
                $lines += "- [ ] $item"
            }
            $lines += ""
        }
    }
    ($lines -join [Environment]::NewLine).TrimEnd() | Set-Content -Encoding UTF8 -Path $PathValue
}

function Invoke-Parse {
    if (-not $InputFile) {
        throw "Missing -Input for parse."
    }
    $doc = Get-StigDocument $InputFile
    if ($Csv) {
        Write-ControlsCsv $doc $Csv
        Write-Host "Controls CSV: $Csv" -ForegroundColor Green
    }
    if ($Json) {
        Write-ControlsJson $doc $Json
        Write-Host "Controls JSON: $Json" -ForegroundColor Green
    }
    if (-not $Csv -and -not $Json) {
        Write-Host "Parsed $($doc.controls.Count) controls from $(Split-Path -Leaf $doc.source_file)." -ForegroundColor Green
    }
}

function Invoke-Diff {
    if (-not $Old -or -not $New) {
        throw "Missing -Old or -New for diff."
    }
    $oldDoc = Get-StigDocument $Old
    $newDoc = Get-StigDocument $New
    $allChanges = @(Compare-StigDocuments $oldDoc $newDoc)
    $changes = @(Select-FilteredChanges $allChanges)
    $briefPath = if ($Markdown) { $Markdown } else { Join-Path $OutDir "change-brief.md" }
    $csvPath = if ($Csv) { $Csv } else { Join-Path $OutDir "remediation-backlog.csv" }
    Write-ChangeBrief $oldDoc $newDoc $changes $briefPath
    Write-BacklogCsv $changes $csvPath
    Write-DiffSummary $oldDoc $newDoc $changes $briefPath $csvPath $allChanges.Count
}

function Invoke-Evidence {
    if (-not $InputFile) {
        throw "Missing -Input for evidence."
    }
    $doc = Get-StigDocument $InputFile
    $path = if ($Markdown) { $Markdown } else { Join-Path $OutDir "evidence-checklist.md" }
    Write-EvidenceChecklist $doc.controls $path
    Write-Host "Evidence checklist: $path" -ForegroundColor Green
}

function Invoke-Packet {
    if (-not $Old -or -not $New) {
        throw "Missing -Old or -New for packet."
    }
    Ensure-Directory $OutDir
    $oldDoc = Get-StigDocument $Old
    $newDoc = Get-StigDocument $New
    $allChanges = @(Compare-StigDocuments $oldDoc $newDoc)
    $changes = @(Select-FilteredChanges $allChanges)

    $briefPath = Join-Path $OutDir "change-brief.md"
    $backlogPath = Join-Path $OutDir "remediation-backlog.csv"
    $jsonPath = Join-Path $OutDir "changes.json"
    $evidencePath = Join-Path $OutDir "evidence-checklist.md"
    $jiraPath = Join-Path $OutDir "jira-import.csv"
    $serviceNowPath = Join-Path $OutDir "servicenow-import.csv"
    $githubPath = Join-Path $OutDir "github-issues.md"

    Write-ChangeBrief $oldDoc $newDoc $changes $briefPath
    Write-BacklogCsv $changes $backlogPath
    Write-ChangesJson $oldDoc $newDoc $changes $jsonPath
    Write-EvidenceChecklist $newDoc.controls $evidencePath
    Write-JiraCsv $changes $jiraPath
    Write-ServiceNowCsv $changes $serviceNowPath
    Write-GitHubIssuesMarkdown $changes $githubPath

    Write-DiffSummary $oldDoc $newDoc $changes $briefPath $backlogPath $allChanges.Count
    Write-Host "Changes JSON: $jsonPath" -ForegroundColor Green
    Write-Host "Evidence checklist: $evidencePath" -ForegroundColor Green
    Write-Host "Jira import CSV: $jiraPath" -ForegroundColor Green
    Write-Host "ServiceNow import CSV: $serviceNowPath" -ForegroundColor Green
    Write-Host "GitHub issue drafts: $githubPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Start here: $briefPath" -ForegroundColor Cyan
}

function Write-DiffSummary {
    param($OldDoc, $NewDoc, $Changes, [string]$BriefPath, [string]$BacklogPath, [int]$UnfilteredCount = -1)
    $counts = Get-ChangeCounts $Changes
    Write-Host ""
    Write-Host "STIGPilot Government Mode Diff Summary" -ForegroundColor Cyan
    Write-Host ("Old controls:                 {0}" -f $OldDoc.controls.Count)
    Write-Host ("New controls:                 {0}" -f $NewDoc.controls.Count)
    if ($UnfilteredCount -ge 0 -and (($Impact) -or ($Owner))) {
        Write-Host ("Unfiltered changes:           {0}" -f $UnfilteredCount)
        if ($Impact) {
            Write-Host ("Impact filter:                {0}" -f $Impact)
        }
        if ($Owner) {
            Write-Host ("Owner filter:                 {0}" -f $Owner)
        }
    }
    Write-Host ("Total changes:                {0}" -f $counts.total)
    Write-Host ("Added:                        {0}" -f $counts.added)
    Write-Host ("Removed:                      {0}" -f $counts.removed)
    Write-Host ("Modified:                     {0}" -f $counts.modified)
    Write-Host ("Severity increased:           {0}" -f $counts.severity_increased)
    Write-Host ("High-priority review:         {0}" -f $counts.high_priority_review)
    Write-Host ("Implementation change likely: {0}" -f $counts.implementation_change_likely)
    Write-Host ("Evidence update likely:       {0}" -f $counts.evidence_update_likely)
    Write-Host ""
    Write-Host "Change brief: $BriefPath" -ForegroundColor Green
    Write-Host "Backlog CSV:   $BacklogPath" -ForegroundColor Green
}

try {
    switch ($Command) {
        "help" { Write-GovHelp }
        "parse" { Invoke-Parse }
        "diff" { Invoke-Diff }
        "evidence" { Invoke-Evidence }
        "packet" { Invoke-Packet }
    }
}
catch {
    Write-Host "STIGPilot Government Mode error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
