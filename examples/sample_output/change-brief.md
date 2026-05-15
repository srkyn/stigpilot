# STIGPilot Change Brief

Old source: `synthetic_old.xml`
New source: `synthetic_new.xml`
Total controls old: 2
Total controls new: 2

## Change Summary

- Added: 1
- Removed: 1
- Modified: 1
- Severity changed: 1
- High-priority review: 2
- Implementation change likely: 0
- Evidence update likely: 0

## Top Priority Actions

- **high_priority_review**: V-100004 - Firewall management access must be restricted (The control is new or now rated high severity.)
- **high_priority_review**: V-100001 - Windows audit policy must be configured and reviewed (The control is new or now rated high severity.)

## Detailed Changes

| Change | Impact | Severity | Vuln ID | Rule ID | Changed Fields | Owner | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| added | high_priority_review | high | V-100004 | SV-100004r1_rule | - | Network/Security Engineering | The control is new or now rated high severity. |
| removed | review_recommended | low | V-100002 | SV-100002r1_rule | - | Linux Admin | The control was removed and downstream tickets or evidence mappings may need cleanup. |
| modified | high_priority_review | high | V-100001 | SV-100001r2_rule | title, severity, check_text, fix_text | Endpoint/Windows Admin | The control is new or now rated high severity. |
