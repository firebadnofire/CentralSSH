# CentralSSH v2 — Transparent SSH Gateway Rework Specification

## Purpose

CentralSSH v2 is a security-critical SSH gateway for highly sandboxed environments such as FreeBSD jails. It provides:

* centralized authentication
* per-user authorization to internal SSH targets
* secure custody of target private keys
* transparent proxying of SSH functionality after target selection

This project is **not** a shell server, **not** a toy TUI, and **not** a limited SSH subset. It is a hardened infrastructure component that must preserve normal SSH behavior while enforcing gateway-side identity and policy.

The previous implementation and its guiding document incorrectly constrained the system into a shell-only broker. This rewrite replaces that design entirely.

---

## Critical Design Rule

After authentication and target selection, CentralSSH must behave like a transparent SSH gateway that is as close as practical to a direct SSH connection from the client to the target.

That means the gateway must preserve standard OpenSSH expectations, including:

* interactive shells
* exec requests
* SFTP
* local forwarding (`ssh -L`)
* remote forwarding (`ssh -R`)
* ncurses applications such as `vim`, `tmux`, `top`, `less`
* PTY resizing and related terminal behavior

If a feature normally works over standard SSH and is not explicitly forbidden by policy, assume it must work through CentralSSH.

---

## Non-Negotiable Corrections from the Previous Spec

The old design guidance was wrong in these ways:

* It forbade SFTP
* It forbade port forwarding
* It forbade subsystems
* It assumed shell-only proxying
* It treated the gateway as a session terminator instead of a protocol bridge

Do not preserve those assumptions.

CentralSSH v2 must be designed around **SSH protocol correctness**, not around a menu-driven shell abstraction.

---

# 1. Product Definition

## What CentralSSH v2 is

CentralSSH v2 is a gateway that:

1. Authenticates the user locally
2. Determines which targets that user may access
3. Lets the user select a target host
4. Connects to that target using a private key stored by the gateway
5. Transparently bridges SSH channels, requests, and traffic between client and target

## What CentralSSH v2 is not

It is not:

* a general Unix login service
* a shell on the gateway host
* an SSH history browser
* a wrapper around the local `ssh` command
* a system that asks the user to manage target keys manually
* a web UI, REST API, or control panel

---

# 2. Architecture

## Connection Model

Required high-level model:

```text
Client <-> CentralSSH <-> Target Server
```

CentralSSH is the trust boundary and policy enforcement point.

## Hard Architectural Requirement

CentralSSH must authenticate and authorize the client itself, but once a target is selected it must stop behaving like an application-level shell broker and instead behave like an SSH protocol proxy.

Do not reduce the target connection to a single shell stream unless the client specifically requested a shell.

### Forbidden architectural shortcut

The gateway must not implement only:

* outbound `session` channel
* fixed PTY
* shell request only
* raw byte copying between two shell streams

That approach is insufficient because it breaks SFTP, exec, forwarding, and protocol-correct SSH behavior.

---

# 3. Protocol Compatibility Requirements

## Standards Goal

CentralSSH must remain compatible with ordinary OpenSSH clients without requiring any custom client software or protocol extensions.

The user must be able to use normal tools such as:

* `ssh`
* `scp`
* `sftp`
* `rsync -e ssh`
* tools relying on `ssh -L` or `ssh -R`
* terminal workflows using `vim`, `tmux`, or other ncurses apps

## Required Client-Side Behavior

The gateway must accept and correctly relay, at minimum, these SSH features.

### Required channel types

* `session`
* `direct-tcpip`
* `forwarded-tcpip`
* any additional standard channel types needed by the chosen SSH library for correct forwarding behavior

### Required session requests

* `pty-req`
* `shell`
* `exec`
* `subsystem`
* `window-change`
* `env` should be supported if the chosen library exposes it safely and relay is feasible

### Required subsystem support

* SFTP must work through the gateway

### Required forwarding support

* local forwarding (`ssh -L`)
* remote forwarding (`ssh -R`)

Agent forwarding is optional and should default to disabled unless there is a strong, explicitly implemented security model for it.

## Protocol correctness rules

The gateway must not:

* silently drop valid SSH requests that should be forwarded
* reinterpret SFTP as shell commands
* fake shell success for non-shell clients
* advertise capabilities it cannot actually support
* close the whole proxied session just because one byte stream direction closed first

---

# 4. Authentication Model

## Gateway Authentication Requirements

Before target selection, the gateway must authenticate the user locally using:

* username
* password
* TOTP (RFC 6238)

Password verification must use Argon2id.

### Password storage requirements

Passwords must be stored only as Argon2id hashes with:

* unique per-user random salt
* memory-hard parameters suitable for server use
* no downgrade path to plaintext or weak hashes

Forbidden:

* plaintext password storage
* SHA-2-only password hashing
* reversible password encryption
* logging password material or derived secrets

### TOTP requirements

TOTP must:

* follow RFC 6238
* use 30-second steps
* allow limited clock skew
* use random high-entropy secrets
* store secrets base32-encoded
* never log raw secrets

## Authentication state rules

Authentication must be a single explicit state machine.

Required rules:

* no fallback auth path that bypasses part of the normal flow
* no “partially authenticated” session may reach target selection
* password success alone is not enough when TOTP is required
* target access must not occur until authentication is fully complete

Transport auth may use keyboard-interactive if needed for compatibility. That is acceptable. But whatever transport method is used, the implementation must not split trust ambiguously across multiple loosely coordinated auth layers.

---

# 5. First-Login and Credential Lifecycle

## Bootstrap provisioning

Administrators may provision users with either:

* a temporary plaintext bootstrap password
* or a precomputed Argon2id hash

If plaintext bootstrap passwords are allowed at all, they are a temporary admin convenience only.

### Required bootstrap handling

If a plaintext bootstrap password appears in config:

* it must be hashed on first secure load
* plaintext must never be written back to disk
* the config file must be atomically rewritten immediately
* the account must remain flagged for required password change

## First-login flow

A user flagged for bootstrap setup must complete, in this order:

1. password change
2. TOTP enrollment
3. verification of the enrolled TOTP
4. atomic persistence of the updated credential state

The user must not gain access to any target until all required first-login steps complete successfully.

## Atomicity requirement

Credential-state persistence for first-login flows must be treated carefully.

The implementation should avoid persisting a half-finished bootstrap state where one part of setup is committed and another part is not, unless there is a deliberate and documented recovery-safe design. Prefer a single atomic credential update when possible.

---

# 6. Authorization Model

## Access structure

The conceptual model is:

```text
user
  └── servers
        └── credentials
```

For implementation purposes, the gateway must think in terms of per-user target access.

### Required policy rules

* Every user has an explicit allowed server list
* Each user/server pair uses credentials specific to that user
* Multiple users may access the same target host, but key material remains per-user
* Authorization is deny-by-default
* If a server is not in the user’s allowed list, the user must not be able to reach it by any path

## Selection model

After authentication, the user must be shown a list of allowed targets and choose one target before the proxied target session begins.

This selection UX may be text-based, but it must remain minimal and must not become a pseudo-shell environment.

---

# 7. Target Selection UX

## Required behavior

After full authentication, present:

* gateway banner
* authenticated username
* numbered list of allowed targets
* prompt for selection

Example:

```text
CentralSSH Gateway
User: alice

Select a server:

1) git (192.168.86.44)
2) httpd (192.168.86.41)

Enter selection: _
```

## UX constraints

The pre-target interface should do as little as necessary:

* authenticate
* force first-login setup if needed
* select target

After the target is selected, the gateway should stop acting like a TUI workflow and instead begin transparent protocol bridging.

---

# 8. Target Connection and Proxying

## Outbound target auth

The gateway is responsible for authenticating to the target host.

The user must not supply target passwords or target private keys interactively.

Required model:

* gateway loads the stored private key for the authenticated user and selected target
* gateway connects to the target over SSH
* gateway verifies the target host key against managed trust data
* gateway performs target authentication

## Host key verification

Host key verification is mandatory.

The gateway must not do blind trust of target hosts at connection time.

Required:

* managed known-hosts style trust store
* strict host key verification against that store
* clear operator-facing failure reporting when trust data is missing or mismatched

Forbidden:

* silent trust-on-first-use at runtime without explicit admin action
* accepting changed host keys automatically

## Transparent relay requirement

After target connection is established, the gateway must relay SSH protocol behavior correctly.

This means:

* forwarding channel opens to the target as appropriate
* forwarding per-channel requests appropriately
* relaying data in both directions until both sides are fully drained or the SSH protocol semantics dictate closure
* preserving correct behavior for PTY, shell, exec, subsystem, and forwarding workflows

## PTY behavior

The gateway must not impose a fixed PTY size or static terminal assumption.

Required:

* forward PTY requests with requested terminal type and dimensions
* forward window-size changes to the target
* preserve terminal behavior needed for ncurses applications

## Exec behavior

If the client requests an exec command, the gateway must forward that exec semantics correctly to the target rather than forcing shell mode.

## Subsystem behavior

If the client requests SFTP, the gateway must forward subsystem semantics correctly so that SFTP behaves normally.

## Forwarding behavior

Forwarding must be implemented intentionally.

Required:

* `ssh -L` behavior via `direct-tcpip`
* `ssh -R` behavior via the corresponding SSH forwarding support

If policy restrictions are later added for forwarding destinations or ports, those restrictions must be explicit, enforceable, and documented. Do not fake support.

---

# 9. Security Boundaries

## Gateway host exposure rules

The gateway must not expose shell access to the system hosting the gateway process.

Users must never gain:

* shell on the gateway host
* filesystem access on the gateway host
* command execution on the gateway host
* visibility into config or stored keys

The only interactive environment the user should ever reach after target selection is the selected target host.

## Filesystem and secret handling

### Config files

All config files must:

* be owned by root
* be mode 0600
* be regular files
* be symlink-checked, not just metadata-checked through symlink resolution

### Private key storage

Private key directories must:

* be outside user-accessible paths
* be root-owned
* be mode 0700 at the directory level
* protect private keys with mode 0600
* reject unsafe path traversal or malformed username/server path components

### Key location

Private key directories should live outside `/etc/centralssh` to keep configuration and secret key storage separated.

Suggested layout:

* `/etc/centralssh/` for config and trust files
* `/var/lib/centralssh/keys/` for private key material
* `/var/log/centralssh/` for audit logs

## Secret handling in memory

Use secure memory handling where practical.

Recommended:

* zeroize password buffers after use
* avoid unnecessary cloning of secrets
* do not log secrets or full auth payloads

---

# 10. Configuration Files

## Base directory

Primary configuration should live under `/etc/centralssh/`.

## Required config files

### `/etc/centralssh/config.json`

Defines users and their credential state.

Example structure:

```json
{
  "users": [
    {
      "name": "alice",
      "password": "$argon2id$...",
      "totp_secret": null,
      "must_change_password": true,
      "allowed_servers": ["git", "httpd"]
    }
  ]
}
```

### `/etc/centralssh/servers.json`

Defines logical target names and their hostnames or IPs.

Example:

```json
{
  "servers": {
    "git": "192.168.86.44",
    "httpd": "192.168.86.41",
    "dns": "192.168.86.53"
  }
}
```

### Known-hosts style trust data

A dedicated trust file must exist for validating target host keys.

## Config validation requirements

Validate configuration at load time as much as practical.

Required validation includes:

* usernames are unique and syntactically safe
* every user has at least one allowed server unless intentionally disabled
* every allowed server exists in `servers.json`
* password fields are valid Argon2id hashes or an explicitly recognized bootstrap form
* TOTP secrets, if present, are valid and parseable
* server identifiers are syntactically valid hostnames or IP literals as required by the implementation

Avoid deferring obviously bad config into random runtime failures later.

---

# 11. Safe Config Mutation Rules

CentralSSH is allowed to mutate config only for credential lifecycle and closely related state updates.

Required write procedure:

1. write a temporary file in the same directory
2. set strict permissions on creation
3. write complete new content
4. fsync the temp file
5. preserve ownership and intended mode
6. atomically rename over the old file
7. fsync the parent directory

Forbidden:

* in-place edits
* partial writes
* best-effort writes without durability steps

All file security checks should use symlink-aware APIs where relevant.

---

# 12. Audit Logging

## Required goals

The gateway must maintain a structured audit log suitable for security review.

Recommended format:

* JSON Lines

## Required logged events

At minimum:

* auth attempt success/failure
* TOTP success/failure
* lockouts or rate-limit denials
* password changes
* TOTP enrollment
* target selection
* successful proxy session start
* proxy session end
* config reload success/failure

## Forbidden audit behavior

Do not log:

* plaintext passwords
* TOTP secrets
* full private key material
* raw secret-bearing request payloads

## File security

Audit logs must be root-owned and permission-restricted.

---

# 13. Rate Limiting and Abuse Controls

The gateway must defend against brute-force authentication attempts.

Required:

* per-user and/or per-IP rate limiting
* bounded memory for rate-limit state
* cleanup of stale limiter entries
* constant-time behavior where practical for username existence and password verification paths

Do not leak easy username enumeration signals if avoidable.

---

# 14. Reload Behavior

Runtime config reload is allowed and useful, but it must be safe.

Required semantics:

* invalid config must not replace the current active config
* reload success/failure must be audited
* newly authenticated sessions must see the latest valid config
* already proxied target sessions do not need live mutation mid-flight unless explicitly designed

---

# 15. Implementation Strategy

## Strong recommendation

Use one coherent authentication state machine and one coherent proxy model.

Avoid the prior design mistake of having:

* transport auth that partly authenticates a user
* then a second app-layer auth path with overlapping logic

That overlap increases complexity and weakens trust-boundary clarity.

## Preferred decomposition

### Authentication engine

Responsibilities:

* username/password verification
* TOTP verification
* first-login enforcement
* rate limiting
* auth result reporting

### Authorization engine

Responsibilities:

* allowed-target resolution
* validation of user-to-target policy

### SSH protocol bridge

Responsibilities:

* open outbound target connection
* verify host key
* authenticate with stored private key
* map and relay SSH channels/requests correctly
* preserve protocol semantics for shell, exec, subsystem, PTY, and forwarding

### Key manager

Responsibilities:

* resolve per-user/per-server key paths safely
* load private keys securely
* validate file permissions and ownership

### Config store

Responsibilities:

* load/validate config
* expose immutable snapshots or safe shared state
* apply credential updates atomically
* support validated reload

### Audit logger

Responsibilities:

* structured event writes
* restricted file handling
* flush/durability behavior appropriate for security logging

---

# 16. Key Management Rules

## Per-user per-server key model

The gateway must think in terms of per-user per-server credentials.

That means:

* if two users can access the same target host, their key material is still distinct
* do not collapse the conceptual security model into host-global credentials unless there is an explicit, documented reason and policy model to do so

## Key generation policy

Auto-generation of target keys must be deterministic and occur at startup.

The system must not rely on manual key provisioning for normal operation.

### Required startup key provisioning behavior

On server startup, CentralSSH must:

1. Enumerate all users defined in `/etc/centralssh/config.json`
2. Resolve each user’s key directory under `centralssh_user_key_root`
3. For every user and every allowed server:

   * If the key **does not exist**:

     * Create the user key directory if it does not exist
     * Ensure directory permissions are set to 0700 and owned by root
     * Generate a new private key for that user/server pair
     * Persist the key with permissions set to 0600

   * If the key **already exists**:

     * Do nothing
     * Do not modify, regenerate, rotate, or overwrite the key under any circumstance

### Non-negotiable constraints

* Existing keys must be treated as authoritative and immutable
* The system must never overwrite or replace an existing private key automatically
* Key generation must be idempotent across restarts
* Startup must not fail solely due to missing keys if they can be generated

### Failure conditions

Startup must fail with a clear error if:

* The key directory cannot be created securely
* Permissions or ownership are unsafe
* Key generation fails

---

# 17. Threat Model

Assume attackers may:

* control network input to the gateway
* brute-force auth attempts
* try malformed SSH messages and protocol edge cases
* obtain read access to improperly secured files if filesystem checks are weak
* attempt lateral movement through forwarding or target-selection flaws

The system must protect against:

* credential theft
* key exfiltration
* privilege escalation on the gateway host
* unauthorized target access
* host-key trust bypass
* incorrect forwarding of unauthorized traffic

---

# 18. Forbidden Practices

Do not implement any of the following:

* shelling out to `ssh`, `sftp`, or system utilities for core gateway behavior
* wrapping the local `ssh` binary instead of implementing the gateway in Rust
* exposing gateway shell access for convenience
* storing plaintext secrets in config or logs
* advertising support for SFTP or forwarding without implementing it correctly
* hardcoding PTY size
* closing proxied sessions based on a single one-shot wall-clock timeout labeled as idle timeout
* ending the entire relay as soon as either stream direction finishes if protocol semantics require a proper half-close/drain

---

# 19. Testing Requirements

This project is security-sensitive. Unit tests alone are not enough.

## Minimum automated coverage should include

### Auth tests

* valid login
* invalid username
* invalid password
* invalid TOTP
* rate-limit behavior
* first-login password change
* first-login TOTP enrollment

### Config tests

* secure atomic write behavior
* invalid config rejection
* duplicate user rejection
* invalid server reference rejection
* invalid hash/secret parsing rejection
* symlink safety checks

### Proxy tests

* shell session proxying
* exec proxying
* subsystem proxying for SFTP
* PTY resize forwarding
* local forwarding behavior
* remote forwarding behavior if implemented
* relay correctness when one side closes first

### Security tests

* host-key mismatch rejection
* missing key rejection
* unsafe file mode rejection
* unsafe ownership rejection
* unsafe symlink/path rejection

## Manual or integration testing should include

* OpenSSH interactive shell
* `scp`
* `sftp`
* `ssh -L`
* `ssh -R` if supported in current phase
* `vim` or `tmux`
* long-lived sessions beyond 30 minutes

---

# 20. Recommended Libraries

Suggested Rust crates include:

* `argon2` for password hashing
* `totp-rs` for TOTP
* `serde` and `serde_json` for configuration
* `zeroize` for secret cleanup
* `tokio` for async runtime
* an SSH library capable of both server- and client-side behavior with enough control to correctly proxy channels and requests

Library choice is secondary to protocol correctness. Do not choose a library that makes required SSH features impossible.

---

# 21. Success Criteria

CentralSSH v2 is complete only when all of the following are true:

* users authenticate with password + TOTP securely
* users only see targets they are authorized to access
* users never get shell access to the gateway host
* the gateway authenticates to targets using securely stored per-user keys
* host key verification is strict
* interactive shells work
* exec requests work
* SFTP works
* SSH forwarding required by policy works
* ncurses terminal behavior works correctly
* config mutation is atomic and secure
* logging is structured and does not leak secrets
* invalid config and unsafe filesystem state are rejected safely

---

# 22. Guiding Philosophy

This project prioritizes:

* security over convenience
* protocol correctness over superficial completeness
* explicit trust boundaries over clever shortcuts
* transparent SSH behavior over shell-only approximations
* minimal attack surface over feature sprawl

CentralSSH v2 should feel boring in the best possible way:

* the client sees normal SSH behavior
* the operator sees explicit policy and auditability
* the gateway host stays hidden and locked down

Build the real thing, not a demo that merely resembles SSH.
