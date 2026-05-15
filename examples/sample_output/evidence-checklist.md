# STIGPilot Evidence Checklist

Source: `new.xml`
Controls included: 3

## V-100001 - Windows audit policy must be configured and reviewed

- Severity: high
- Suggested owner: Endpoint/Windows Admin
- Tags: Audit Logging, Endpoint Security, Windows, GPO
- Check summary: Review Windows audit policy settings in Local Security Policy and export applied GPO evidence.
- Evidence requested:
  - Screenshot or export of the relevant setting
  - GPO, registry, or Local Security Policy export
  - Date/time of validation
  - System or asset name
  - Reviewer notes

## V-100002 - Linux SSH banner must be configured

- Severity: low
- Suggested owner: Linux Admin
- Tags: Remote Access, Linux
- Check summary: Run sshd -T and review the banner setting and file permissions.
- Evidence requested:
  - Screenshot or export of the relevant setting
  - Command output showing the configured value
  - Relevant policy or configuration file excerpt
  - Date/time of validation
  - System or asset name
  - Reviewer notes

## V-100004 - Firewall management access must be restricted

- Severity: high
- Suggested owner: Network/Security Engineering
- Tags: Network Security
- Check summary: Review firewall management network restrictions and approved admin source ranges.
- Evidence requested:
  - Screenshot or export of the relevant setting
  - Network device configuration excerpt or management console export
  - Date/time of validation
  - System or asset name
  - Reviewer notes
