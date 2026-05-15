# STIGPilot Evidence Checklist

Source: `new.xml`
Controls included: 3

## Endpoint/Windows Admin

### V-CHROME-001 - Chrome Safe Browsing enhanced protection must be enabled

- Severity: high
- Rule ID: SV-CHROME-001r2_rule
- Tags: IAM, Endpoint Security, GPO, Registry, Browser Security
- Check summary: Review Chrome enterprise policy in GPO or registry and export evidence showing SafeBrowsingProtectionLevel is set to enhanced protection.

Validation metadata:

- [ ] Asset/System:
- [ ] Environment:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-CHROME-002 - Chrome password manager must be disabled

- Severity: medium
- Rule ID: SV-CHROME-002r2_rule
- Tags: Password Policy, GPO, Registry, Browser Security
- Check summary: Review Chrome enterprise policy in GPO or registry and export evidence showing PasswordManagerEnabled is disabled for managed users.

Validation metadata:

- [ ] Asset/System:
- [ ] Environment:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### V-CHROME-004 - Chrome extension installation must be restricted

- Severity: high
- Rule ID: SV-CHROME-004r1_rule
- Tags: GPO, Registry, Browser Security
- Check summary: Review Chrome enterprise extension policy and confirm unapproved extension installation is blocked or allowlisted.

Validation metadata:

- [ ] Asset/System:
- [ ] Environment:
- [ ] Validated by:
- [ ] Date:
- [ ] Notes:

Evidence requested:
- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes
