# STIGPilot Change Brief

Old source: `old.xml`
New source: `new.xml`
Total controls old: 3
Total controls new: 3

## Change Summary

- Added: 1
- Removed: 1
- Modified: 2
- Severity changed: 1
- Check text changed: 2
- Fix text changed: 1
- High-priority review: 2
- Implementation change likely: 0
- Evidence update likely: 1
- Review recommended: 1
- No action likely: 0

## Manager Summary

4 control change(s) were detected. 3 likely require priority review, implementation work, or evidence updates. The most affected owner group is multiple owner groups. Use the backlog CSV to assign review work and the evidence checklist to prepare validation requests.

## Top Priority Actions

- **high_priority_review**: V-100004 - Firewall management access must be restricted (New high severity control; triage ownership, implementation, and evidence first.)
- **high_priority_review**: V-100001 - Windows audit policy must be configured and reviewed (Severity increased to high and fix guidance changed; prioritize analyst and implementation owner review.)
- **evidence_update_likely**: V-100002 - Linux SSH banner must be configured (Check guidance changed meaningfully; validation evidence may need updates.)

## Detailed Changes

| Change | Impact | Severity | Vuln ID | Rule ID | Changed Fields | Owner | Tags | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| added | high_priority_review | high | V-100004 | SV-100004r1_rule | - | Network/Security Engineering | Network Security | New high severity control; triage ownership, implementation, and evidence first. |
| removed | review_recommended | medium | V-100003 | SV-100003r1_rule | - | Database Admin | Audit Logging, Database | The control was removed and downstream tickets or evidence mappings may need cleanup. |
| modified | high_priority_review | high | V-100001 | SV-100001r2_rule | title, severity, check_text, fix_text, references | Endpoint/Windows Admin | Audit Logging, Endpoint Security, Windows, GPO | Severity increased to high and fix guidance changed; prioritize analyst and implementation owner review. |
| modified | evidence_update_likely | low | V-100002 | SV-100002r2_rule | check_text | Linux Admin | Remote Access, Linux | Check guidance changed meaningfully; validation evidence may need updates. |
