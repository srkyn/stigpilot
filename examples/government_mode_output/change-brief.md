# STIGPilot Government Mode Change Brief

## Executive Summary

4 control change(s) were detected between the supplied XCCDF files. 2 change(s) need high-priority review, 0 likely require implementation review, and 1 likely require refreshed evidence. The most affected owner group is Linux Admin. Use this as local triage support; it does not scan systems or validate compliance.

## Source Files

- Old source: `old.xml`
- New source: `new.xml`
- Old controls: 3
- New controls: 3

## At-a-Glance

| Metric | Count |
| --- | ---: |
| Added controls | 1 |
| Removed controls | 1 |
| Modified controls | 2 |
| Severity increases | 1 |
| High-priority review | 2 |
| Implementation change likely | 0 |
| Evidence update likely | 1 |

## Priority Actions

1. **V-100001 - Windows audit policy must be configured and reviewed**
   - Impact: High-priority review
   - Owner: Endpoint/Windows Admin
   - Why it matters: The severity increased, so the control should be reviewed before reusing old risk notes, tickets, or evidence.
2. **V-100004 - Firewall management access must be restricted**
   - Impact: High-priority review
   - Owner: Network/Security Engineering
   - Why it matters: A new high-severity control was added, so it should be reviewed before lower-risk backlog items.
3. **V-100002 - Linux SSH banner must be configured**
   - Impact: Evidence update likely
   - Owner: Linux Admin
   - Why it matters: The validation steps changed enough that evidence requests may need to be refreshed.
4. **V-100003 - Removed database audit control**
   - Impact: Review recommended
   - Owner: Database Admin
   - Why it matters: The control was removed from the newer file; review whether open tickets or evidence requests can be closed or retired.

## Owner Impact

| Owner | Changes | High Priority | Implementation Likely | Evidence Updates |
| --- | ---: | ---: | ---: | ---: |
| Linux Admin | 1 | 0 | 0 | 1 |
| Database Admin | 1 | 0 | 0 | 0 |
| Endpoint/Windows Admin | 1 | 1 | 0 | 0 |
| Network/Security Engineering | 1 | 1 | 0 | 0 |

## Detailed Changes

| Change Type | Impact | Severity | Vuln ID | Rule ID | Title | Owner | Why it matters |
| --- | --- | --- | --- | --- | --- | --- | --- |
| severity_increased | High-priority review | high | V-100001 | SV-100001r2_rule | Windows audit policy must be configured and reviewed | Endpoint/Windows Admin | The severity increased, so the control should be reviewed before reusing old risk notes, tickets, or evidence. |
| added | High-priority review | high | V-100004 | SV-100004r1_rule | Firewall management access must be restricted | Network/Security Engineering | A new high-severity control was added, so it should be reviewed before lower-risk backlog items. |
| modified | Evidence update likely | low | V-100002 | SV-100002r2_rule | Linux SSH banner must be configured | Linux Admin | The validation steps changed enough that evidence requests may need to be refreshed. |
| removed | Review recommended | medium | V-100003 | SV-100003r1_rule | Removed database audit control | Database Admin | The control was removed from the newer file; review whether open tickets or evidence requests can be closed or retired. |
