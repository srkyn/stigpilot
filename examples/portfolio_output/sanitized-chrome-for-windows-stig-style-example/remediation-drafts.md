# STIGPilot Remediation Drafts

> Review-only planning notes. STIGPilot does not apply changes, run commands, edit policy, restart services, or modify hosts.

Use these drafts to prepare owner review, change-control notes, implementation tickets, and evidence requests. Validate every item against the local environment before any change is made.

## Draft 1: V-CHROME-004

**Title:** Chrome extension installation must be restricted
**Impact:** High-priority review (`high_priority_review`)
**Suggested owner:** Endpoint/Windows Admin
**Change type:** added
**Why it matters:** A new high-severity control was added, so it should be triaged before lower-risk backlog work.

### Draft Remediation Note

Configure Chrome ExtensionInstallBlocklist and ExtensionInstallAllowlist policies through GPO or registry.

### Review Before Action

- [ ] Confirm the control applies to the local environment.
- [ ] Identify the actual implementation path: local policy, GPO, MDM, configuration management, image build, or compensating control.
- [ ] Test in a safe scope before broad rollout.
- [ ] Document rollback or exception handling.
- [ ] Update evidence only after the approved implementation path is confirmed.

### Evidence To Prepare

- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### Boundary

- Changes made by STIGPilot: none.
- This draft is not an executable patch.

## Draft 2: V-CHROME-003

**Title:** Deprecated Chrome cleanup policy must be reviewed
**Impact:** Review recommended (`review_recommended`)
**Suggested owner:** Security/GRC Analyst
**Change type:** removed
**Why it matters:** The control was removed, so downstream tickets, evidence requests, or mappings may need cleanup.

### Draft Remediation Note

The control was removed from the compared release. Review downstream tickets, evidence requests, mappings, and local exceptions before closing or archiving related work.

### Review Before Action

- [ ] Confirm the control is actually removed from the authoritative release being adopted.
- [ ] Review open tickets, evidence requests, mappings, and exceptions tied to the removed control.
- [ ] Decide whether any local policy still requires the control despite the STIG removal.
- [ ] Document the closure, carry-forward, or exception decision.
- [ ] Do not remove a local control solely because it disappeared from one comparison packet.

### Evidence To Prepare

- [ ] Screenshot or export of the relevant setting
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### Boundary

- Changes made by STIGPilot: none.
- This draft is not an executable patch.

## Draft 3: V-CHROME-001

**Title:** Chrome Safe Browsing enhanced protection must be enabled
**Impact:** High-priority review (`high_priority_review`)
**Suggested owner:** Endpoint/Windows Admin
**Change type:** severity_increased
**Why it matters:** The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review.

### Draft Remediation Note

Configure Chrome Safe Browsing enhanced protection through Group Policy or the registry policy path and document the applied baseline.

### Review Before Action

- [ ] Confirm the control applies to the local environment.
- [ ] Identify the actual implementation path: local policy, GPO, MDM, configuration management, image build, or compensating control.
- [ ] Test in a safe scope before broad rollout.
- [ ] Document rollback or exception handling.
- [ ] Update evidence only after the approved implementation path is confirmed.

### Evidence To Prepare

- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### Boundary

- Changes made by STIGPilot: none.
- This draft is not an executable patch.

## Draft 4: V-CHROME-002

**Title:** Chrome password manager must be disabled
**Impact:** Evidence update likely (`evidence_update_likely`)
**Suggested owner:** Endpoint/Windows Admin
**Change type:** check_changed
**Why it matters:** The check procedure changed enough that evidence requests or validation steps may need to be refreshed.

### Draft Remediation Note

Disable Chrome Password Manager using enterprise policy.

### Review Before Action

- [ ] Confirm the control applies to the local environment.
- [ ] Identify the actual implementation path: local policy, GPO, MDM, configuration management, image build, or compensating control.
- [ ] Test in a safe scope before broad rollout.
- [ ] Document rollback or exception handling.
- [ ] Update evidence only after the approved implementation path is confirmed.

### Evidence To Prepare

- [ ] Screenshot or export of the relevant setting
- [ ] GPO, registry, or Local Security Policy export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### Boundary

- Changes made by STIGPilot: none.
- This draft is not an executable patch.
