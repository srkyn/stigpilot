# STIGPilot Evidence Checklist

Source: `new.xml`
Controls included: 3

## Endpoint/Windows Admin

### V-100001 - Windows audit policy must be configured and reviewed

- Severity: high
- Rule ID: SV-100001r2_rule
- Tags: Audit Logging, Endpoint Security, Windows, GPO
- Check summary: Review Windows audit policy settings in Local Security Policy and export applied GPO evidence.

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

## Linux Admin

### V-100002 - Linux SSH banner must be configured

- Severity: low
- Rule ID: SV-100002r2_rule
- Tags: Remote Access, Linux
- Check summary: Run sshd -T and review the banner setting and file permissions.

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] Command output showing the configured value
- [ ] Relevant policy or configuration file excerpt
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

## Network/Security Engineering

### V-100004 - Firewall management access must be restricted

- Severity: high
- Rule ID: SV-100004r1_rule
- Tags: Network Security
- Check summary: Review firewall management network restrictions and approved admin source ranges.

Validation metadata:

- [ ] Asset/System:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] Network device configuration excerpt or management console export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes
