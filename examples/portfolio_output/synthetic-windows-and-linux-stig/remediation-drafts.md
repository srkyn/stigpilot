# STIGPilot Remediation Drafts

> Review-only planning notes. STIGPilot does not apply changes, run commands, edit policy, restart services, or modify hosts.

Use these drafts to prepare owner review, change-control notes, implementation tickets, and evidence requests. Validate every item against the local environment before any change is made.

## Draft 1: V-100004

**Title:** Firewall management access must be restricted
**Impact:** High-priority review (`high_priority_review`)
**Suggested owner:** Network/Security Engineering
**Change type:** added
**Why it matters:** A new high-severity control was added, so it should be triaged before lower-risk backlog work.

### Draft Remediation Note

Restrict firewall management access to approved networks.

### Review Before Action

- [ ] Confirm the control applies to the local environment.
- [ ] Identify the actual implementation path: local policy, GPO, MDM, configuration management, image build, or compensating control.
- [ ] Test in a safe scope before broad rollout.
- [ ] Document rollback or exception handling.
- [ ] Update evidence only after the approved implementation path is confirmed.

### Evidence To Prepare

- [ ] Screenshot or export of the relevant setting
- [ ] Network device configuration excerpt or management console export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### Boundary

- Changes made by STIGPilot: none.
- This draft is not an executable patch.

## Draft 2: V-100003

**Title:** Removed database audit control
**Impact:** Review recommended (`review_recommended`)
**Suggested owner:** Database Admin
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
- [ ] Database configuration query output or parameter export
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### Boundary

- Changes made by STIGPilot: none.
- This draft is not an executable patch.

## Draft 3: V-100001

**Title:** Windows audit policy must be configured and reviewed
**Impact:** High-priority review (`high_priority_review`)
**Suggested owner:** Endpoint/Windows Admin
**Change type:** severity_increased
**Why it matters:** The severity increased to high and the remediation text changed, so old tickets or implementation notes should not be reused without review.

### Draft Remediation Note

Configure Windows audit policy through GPO and document the applied baseline.

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

## Draft 4: V-100002

**Title:** Linux SSH banner must be configured
**Impact:** Evidence update likely (`evidence_update_likely`)
**Suggested owner:** Linux Admin
**Change type:** check_changed
**Why it matters:** The check procedure changed enough that evidence requests or validation steps may need to be refreshed.

### Draft Remediation Note

Configure the sshd Banner directive in /etc/ssh/sshd_config.

### Review Before Action

- [ ] Confirm the control applies to the local environment.
- [ ] Identify the actual implementation path: local policy, GPO, MDM, configuration management, image build, or compensating control.
- [ ] Test in a safe scope before broad rollout.
- [ ] Document rollback or exception handling.
- [ ] Update evidence only after the approved implementation path is confirmed.

### Evidence To Prepare

- [ ] Screenshot or export of the relevant setting
- [ ] Command output showing the configured value
- [ ] Relevant policy or configuration file excerpt
- [ ] Date/time of validation
- [ ] System or asset name
- [ ] Reviewer notes

### Boundary

- Changes made by STIGPilot: none.
- This draft is not an executable patch.
