# STIGPilot Change Brief

## Executive Summary

4 control change(s) were detected. 3 change(s) are likely to require priority review, implementation work, or evidence refresh. The most affected owner group(s) are Endpoint/Windows Admin, Security/GRC Analyst. Prioritize high-severity additions or severity increases, then review remediation text changes before reusing old tickets.

## Source Files

Old source: `chrome.xml`
New source: `chrome.xml`
Total controls old: 3
Total controls new: 3

## At-a-Glance

| Metric | Count |
| --- | ---: |
| Added controls | 1 |
| Removed controls | 1 |
| Modified controls | 2 |
| Severity changes | 1 |
| High-priority review | 2 |
| Implementation change likely | 0 |
| Evidence update likely | 1 |

## Priority Actions

1. **V-CHROME-001 - Chrome Safe Browsing enhanced protection must be enabled**
   - Impact: High-priority review
   - Owner: Endpoint/Windows Admin
   - Why it matters: The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review.
2. **V-CHROME-004 - Chrome extension installation must be restricted**
   - Impact: High-priority review
   - Owner: Endpoint/Windows Admin
   - Why it matters: A new high-severity control was added, so it should be triaged before lower-risk backlog work.
3. **V-CHROME-002 - Chrome password manager must be disabled**
   - Impact: Evidence update likely
   - Owner: Endpoint/Windows Admin
   - Why it matters: The check procedure changed enough that evidence requests or validation steps may need to be refreshed.
4. **V-CHROME-003 - Deprecated Chrome cleanup policy must be reviewed**
   - Impact: Review recommended
   - Owner: Security/GRC Analyst
   - Why it matters: The control was removed, so downstream tickets, evidence requests, or mappings may need cleanup.

## Owner Impact

| Owner | Changes | High Priority | Implementation Likely | Evidence Updates |
| --- | ---: | ---: | ---: | ---: |
| Endpoint/Windows Admin | 3 | 2 | 0 | 1 |
| Security/GRC Analyst | 1 | 0 | 0 | 0 |

## Change Categories

| Impact | Count | Meaning |
| --- | ---: | --- |
| High-priority review | 2 | Review first because severity or new high-risk scope changed. |
| Implementation change likely | 0 | Remediation steps may need updates before reusing old tickets. |
| Evidence update likely | 1 | Check procedure changed enough that evidence requests may need refresh. |
| Review recommended | 1 | Traceability, cleanup, or analyst review is recommended. |
| No action likely | 0 | Likely wording or metadata only; keep awareness but avoid noisy tickets. |

## Top Changed Controls

| Impact | Severity | Vuln ID | Rule ID | Title | Owner | Why it matters |
| --- | --- | --- | --- | --- | --- | --- |
| High-priority review | high | V-CHROME-001 | SV-CHROME-001r2_rule | Chrome Safe Browsing enhanced protection must be enabled | Endpoint/Windows Admin | The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review. |
| High-priority review | high | V-CHROME-004 | SV-CHROME-004r1_rule | Chrome extension installation must be restricted | Endpoint/Windows Admin | A new high-severity control was added, so it should be triaged before lower-risk backlog work. |
| Evidence update likely | medium | V-CHROME-002 | SV-CHROME-002r2_rule | Chrome password manager must be disabled | Endpoint/Windows Admin | The check procedure changed enough that evidence requests or validation steps may need to be refreshed. |
| Review recommended | low | V-CHROME-003 | SV-CHROME-003r1_rule | Deprecated Chrome cleanup policy must be reviewed | Security/GRC Analyst | The control was removed, so downstream tickets, evidence requests, or mappings may need cleanup. |

## Detailed Changes

| Change Type | Impact | Severity | Vuln ID | Rule ID | Changed Fields | Owner | Why it matters |
| --- | --- | --- | --- | --- | --- | --- | --- |
| added | High-priority review | high | V-CHROME-004 | SV-CHROME-004r1_rule | - | Endpoint/Windows Admin | A new high-severity control was added, so it should be triaged before lower-risk backlog work. |
| removed | Review recommended | low | V-CHROME-003 | SV-CHROME-003r1_rule | - | Security/GRC Analyst | The control was removed, so downstream tickets, evidence requests, or mappings may need cleanup. |
| severity_increased | High-priority review | high | V-CHROME-001 | SV-CHROME-001r2_rule | title, severity, check_text, fix_text, references | Endpoint/Windows Admin | The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review. |
| check_changed | Evidence update likely | medium | V-CHROME-002 | SV-CHROME-002r2_rule | check_text | Endpoint/Windows Admin | The check procedure changed enough that evidence requests or validation steps may need to be refreshed. |
