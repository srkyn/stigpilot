# STIGPilot Change Brief

## Executive Summary

4 control change(s) were detected. 3 change(s) are likely to require priority review, implementation work, or evidence refresh. The most affected owner group(s) are Database Admin, Endpoint/Windows Admin, Linux Admin. Prioritize high-severity additions or severity increases, then review remediation text changes before reusing old tickets.

## Source Files

Old source: `old.xml`
New source: `new.xml`
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

1. **V-100001 - Windows audit policy must be configured and reviewed**
   - Impact: High-priority review
   - Owner: Endpoint/Windows Admin
   - Why it matters: The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review.
2. **V-100004 - Firewall management access must be restricted**
   - Impact: High-priority review
   - Owner: Network/Security Engineering
   - Why it matters: A new high-severity control was added, so it should be triaged before lower-risk backlog work.
3. **V-100002 - Linux SSH banner must be configured**
   - Impact: Evidence update likely
   - Owner: Linux Admin
   - Why it matters: The check procedure changed enough that evidence requests or validation steps may need to be refreshed.
4. **V-100003 - Removed database audit control**
   - Impact: Review recommended
   - Owner: Database Admin
   - Why it matters: The control was removed, so downstream tickets, evidence requests, or mappings may need cleanup.

## Owner Impact

| Owner | Changes | High Priority | Implementation Likely | Evidence Updates |
| --- | ---: | ---: | ---: | ---: |
| Database Admin | 1 | 0 | 0 | 0 |
| Endpoint/Windows Admin | 1 | 1 | 0 | 0 |
| Linux Admin | 1 | 0 | 0 | 1 |
| Network/Security Engineering | 1 | 1 | 0 | 0 |

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
| High-priority review | high | V-100001 | SV-100001r2_rule | Windows audit policy must be configured and reviewed | Endpoint/Windows Admin | The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review. |
| High-priority review | high | V-100004 | SV-100004r1_rule | Firewall management access must be restricted | Network/Security Engineering | A new high-severity control was added, so it should be triaged before lower-risk backlog work. |
| Evidence update likely | low | V-100002 | SV-100002r2_rule | Linux SSH banner must be configured | Linux Admin | The check procedure changed enough that evidence requests or validation steps may need to be refreshed. |
| Review recommended | medium | V-100003 | SV-100003r1_rule | Removed database audit control | Database Admin | The control was removed, so downstream tickets, evidence requests, or mappings may need cleanup. |

## Detailed Changes

| Change Type | Impact | Severity | Vuln ID | Rule ID | Changed Fields | Owner | Why it matters |
| --- | --- | --- | --- | --- | --- | --- | --- |
| added | High-priority review | high | V-100004 | SV-100004r1_rule | - | Network/Security Engineering | A new high-severity control was added, so it should be triaged before lower-risk backlog work. |
| removed | Review recommended | medium | V-100003 | SV-100003r1_rule | - | Database Admin | The control was removed, so downstream tickets, evidence requests, or mappings may need cleanup. |
| severity_increased | High-priority review | high | V-100001 | SV-100001r2_rule | title, severity, check_text, fix_text, references | Endpoint/Windows Admin | The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review. |
| check_changed | Evidence update likely | low | V-100002 | SV-100002r2_rule | check_text | Linux Admin | The check procedure changed enough that evidence requests or validation steps may need to be refreshed. |
