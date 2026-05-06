# CentralSSH — Agent Execution & Design Contract

This document defines how agents must **understand, navigate, and operate** within this repository.

It is not just a design spec. It is a **contract for safe and correct behavior**.

---

# 0. Required Reading Order (MANDATORY)

Before taking any action, an agent must read these files in order:

1. `POLICY.md` → hard safety rules and forbidden actions
2. `ACCESS.md` → environment topology and connection method fileciteturn1file0
3. `RUNBOOK.md` → step-by-step procedures
4. `op-guide.md` → operator expectations and real-world behavior
5. `disection.md` → actual implementation details (source of truth for behavior)
6. `README.md` → high-level overview

Only after reading the above should this file be used for design and implementation decisions.

If any conflict exists:

* `POLICY.md` overrides everything
* runtime behavior (`disection.md`) overrides design intent
* `RUNBOOK.md` defines operational procedure

---

# 1. Purpose

CentralSSH is a **security-critical SSH gateway** designed for environments such as FreeBSD hosts and jails.

It provides:

* centralized authentication (password + TOTP)
* per-user authorization to target hosts
* secure custody of target private keys
* transparent SSH proxying after target selection

This system is not optional infrastructure. It is a **trust boundary**.

---

# 2. Core Execution Rules for Agents

## 2.1 Do Not Guess

* Never assume a resource exists
* Never assume connectivity
* Never assume context (host vs jail)

Always validate before acting.

---

## 2.2 Follow the Runbook

All operational actions must map to `RUNBOOK.md`.

If no matching procedure exists:

* Stop
* Do not improvise

---

## 2.3 Enforce Policy

All actions must comply with `POLICY.md`.

If an action would violate policy:

* Do not perform it
* Do not attempt a workaround

---

## 2.4 Respect Context Boundaries

You are always in one of:

* Host (control plane)
* Jail (runtime)
* Client machine

Crossing these boundaries incorrectly is a critical error.

---

## 2.5 No Silent Failure

* Do not ignore errors
* Do not continue after failure
* Surface issues and stop

---

# 3. Critical Design Rule

After authentication and target selection, CentralSSH must behave as a **transparent SSH proxy**.

It must preserve OpenSSH semantics, including:

* interactive shell
* exec requests
* SFTP
* port forwarding (`-L`, `-R`)
* PTY behavior and resizing
* ncurses applications

If OpenSSH supports it, CentralSSH should support it unless explicitly forbidden.

---

# 4. What CentralSSH Is NOT

CentralSSH must never become:

* a shell host
* a command execution environment
* a wrapper around `ssh`
* a partial SSH implementation

It is a **protocol bridge**, not a user environment.

---

# 5. Architecture Model

```text
Client <-> CentralSSH <-> Target Server
```

CentralSSH is the **trust boundary and enforcement point**.

---

# 6. Operational Awareness

Agents must understand:

* Jails may not exist and must be created via Bastille
* Connectivity may require a jump host
* Keys may be generated automatically at startup
* Config is authoritative but must be validated

Never assume static state.

---

# 7. Security Requirements

## 7.1 Authentication

* Passwords → Argon2id
* TOTP → RFC 6238
* No partial authentication states

## 7.2 Secrets

Never:

* log secrets
* expose private keys
* store plaintext credentials

Startup bootstrap must not mutate config or generate keys until KEK/provider
readiness and `master.key` integrity have been proven, unless
`allow_insecure_boot=true` is explicitly configured and logged as a critical
warning.

Strict mode requires encrypted config secrets and encrypted outbound private-key
files. The `raw-file` KEK provider is never acceptable in strict mode.

## 7.3 Host Key Verification

Must always be enforced.

No trust-on-first-use at runtime.

---

# 8. Proxy Behavior Requirements

CentralSSH must correctly relay:

* session channels
* exec requests
* subsystem (SFTP)
* PTY behavior
* forwarding channels

It must not:

* drop valid requests
* fake success
* degrade protocol behavior

---

# 9. Configuration Rules

* Config must be validated at load time
* Writes must be atomic
* Invalid config must never replace active config
* Encrypted config writes must use context-separated encryption for password and TOTP fields

---

# 10. Key Management Rules

* Keys are per-user per-server
* Keys are generated if missing
* Existing keys are immutable
* Strict-mode private key files must be encrypted at rest

Never overwrite keys.

---

# 11. Failure Rules

Stop immediately if:

* host key mismatch occurs
* config validation fails
* permissions are unsafe
* behavior contradicts expectations

---

# 12. Testing Expectations

Changes must be validated against:

* SSH shell
* exec
* SFTP
* port forwarding
* long-lived sessions

---

# 13. Implementation Strategy

Preferred architecture:

* Authentication engine
* Authorization engine
* SSH proxy layer
* Key manager
* Config store
* Audit logger

Avoid overlapping responsibilities.

---

# 14. Forbidden Practices

Do not:

* shell out to `ssh`
* expose gateway shell access
* store plaintext secrets
* fake protocol support
* hardcode PTY assumptions

---

# 15. Documentation Contract

When code changes:

You must update:

* `README.md`
* `op-guide.md`
* `disection.md`
* this file

When CI or packaging behavior changes, keep the documented source of truth in
sync with the tracked helper scripts under `ci/` and the live workflow in
`.forgejo/workflows/build.yml`.

Documentation must reflect reality.

---

# 16. Success Criteria

The system is correct only when:

* authentication is secure
* authorization is enforced
* proxying is transparent
* host key verification is strict
* secrets are protected
* logs are structured and safe

---

# 17. Final Rule

If you are uncertain:

1. Check POLICY.md
2. Check RUNBOOK.md
3. Verify environment (ACCESS.md)
4. Stop if still unclear

Never proceed based on assumption.
