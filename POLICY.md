# CentralSSH Operational Policy

This document defines **non-negotiable rules and guardrails** for operating CentralSSH and its surrounding environment.

These rules apply to:

* Humans
* Automation
* Agentic systems

If any instruction conflicts with this document, **this policy takes precedence**.

---

# 1. Core Principles

## 1.1 Least Privilege

* Perform actions in the lowest privilege context possible
* Do not escalate to host-level actions unless required

## 1.2 Explicit Context Awareness

Always know where you are operating:

* Host (control plane)
* Jail (runtime)
* Client machine

If context is unclear, **stop and verify before proceeding**.

## 1.3 Deterministic Behavior

* Do not guess
* Do not assume resources exist
* Validate state before acting

---

# 2. Access & Execution Rules

## 2.1 Host vs Jail Separation

### Forbidden

* Running `bastille` inside a jail
* Modifying host networking from inside a jail
* Attempting to access host filesystem paths from a jail

### Required

* Perform all jail lifecycle actions on the host
* Treat jail as an isolated runtime

---

## 2.2 Command Execution Safety

### Never execute:

* Destructive commands without explicit intent:

```
rm -rf /
rm -rf /var/lib/centralssh
```

* Bulk file operations without path verification
* Commands with unexpanded or ambiguous variables

### Always:

* Verify target paths before modification
* Prefer read-only inspection before mutation

---

## 2.3 Idempotency Requirement

All actions should be safe to run multiple times.

* Do not overwrite existing keys
* Do not recreate resources blindly
* Check existence before creation

---

# 3. Authentication & Secrets

## 3.1 Secret Handling

### Forbidden

* Logging passwords
* Logging TOTP secrets
* Logging private keys
* Storing plaintext credentials beyond bootstrap

### Required

* Use Argon2id for password storage
* Use TOTP per RFC 6238
* Store secrets only in approved locations

---

## 3.2 Key Management

### Forbidden

* Modifying or overwriting existing private keys
* Exposing private key contents
* Moving keys outside secured directories

### Required

* Ensure permissions:

  * directories: 0700
  * private keys: 0600
* Treat existing keys as authoritative

---

# 4. Network & Trust Policy

## 4.1 Host Key Verification

### Never:

* Disable host key checking
* Accept unknown keys without verification
* Automatically trust changed keys

### Always:

* Use known_hosts for verification
* Treat mismatches as potential security incidents

---

## 4.2 Jump Host Usage

* Use jump host only when direct connectivity fails
* Do not assume jump host is always required

---

# 5. Configuration Safety

## 5.1 File Integrity

### Required

* Config files must be:

  * regular files
  * not symlinks
  * permission-restricted

### Forbidden

* Editing config in-place without atomic replacement
* Using insecure file permissions

---

## 5.2 Change Control

Before modifying configuration:

* Validate syntax
* Confirm affected users and servers
* Reload and verify

---

# 6. Logging & Audit

## 6.1 Logging Rules

### Must log:

* Authentication attempts
* Failures and bans
* Target selection
* Proxy start/stop

### Must NOT log:

* Secrets
* Private keys
* Raw auth payloads

---

## 6.2 Audit Integrity

* Logs must be append-only
* Logs must be permission-restricted

---

# 7. Failure Handling

## 7.1 Stop Conditions

Immediately stop if:

* Host key mismatch occurs
* Config validation fails
* Unexpected permission errors occur
* Authentication behaves inconsistently

---

## 7.2 Safe Recovery

* Prefer rollback over patching unknown state
* Restore known-good configuration
* Restart services cleanly

---

# 8. Operational Boundaries

## 8.1 Gateway Restrictions

Users must never gain:

* Shell access to gateway host
* Access to gateway filesystem
* Ability to execute commands on gateway

---

## 8.2 Proxy Behavior

The gateway must:

* Transparently relay SSH protocol behavior
* Not degrade SSH features (SFTP, exec, forwarding)

---

# 9. Decision Rules

When unsure:

1. Check ENVIRONMENT.md for context
2. Check RUNBOOK.md for procedure
3. If still unclear → stop

Never proceed based on assumption.

---

# 10. Enforcement

Violations of this policy:

* Must be treated as operational faults
* Require immediate correction
* Should trigger review of procedures

---

# Summary

This policy exists to:

* Prevent unsafe operations
* Preserve system integrity
* Enforce correct boundaries

If a task cannot be completed without violating this policy, **do not perform the task**.

