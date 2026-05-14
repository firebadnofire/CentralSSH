# CentralSSH Internal Disection

This document describes the current implementation in this repository as it exists today. It is an implementation map, not a target-state design spec. If this file disagrees with `README.md`, `op-guide.md`, or `AGENTS.md`, the code under `src/` is the source of truth and the docs need to be reconciled.

`AGENTS.md` requires documentation to stay synchronized when the program changes. Treat this file as part of that synchronized set with `README.md` and `op-guide.md`; update all three in the same change when implementation behavior changes.

## 1. Repository shape

Main runtime modules:

- `src/main.rs`: process startup, CLI parsing, path resolution, bootstrap, reload task, and SSH server launch.
- `src/app.rs`: shared application state and startup bootstrap helpers.
- `src/config/mod.rs`: config models, path resolution, semantic validation, file security checks, and atomic config writes.
- `src/auth/mod.rs`: Argon2id password handling, TOTP handling, and in-memory token-bucket rate limiting.
- `src/abuse.rs`: fail2ban-style IP abuse tracking, tarpitting, ban persistence, and whitelist loading.
- `src/audit/mod.rs`: JSONL audit logging with file security enforcement.
- `src/keys/mod.rs`: outbound per-user key path resolution and idempotent startup key generation.
- `src/ssh/mod.rs`: SSH server, keyboard-interactive auth state machine, target selection flow, and server host key management.
- `src/ssh/proxy.rs`: outbound SSH client connection and transparent channel/request bridging to the selected target.
- `src/reload/mod.rs`: `SIGHUP` reload notifier.
- `src/crypto_policy.rs`: SSH transport algorithm policy and rekey limits.
- `src/ui/mod.rs`: generic prompt/banner helpers and QR rendering helpers. Much of the live auth UX now happens in `src/ssh/mod.rs`.

Support files:

- `AGENTS.md`: target-state design rules and repository instruction source.
- `README.md`: user-oriented overview and installation notes.
- `op-guide.md`: operator workflow and troubleshooting guide.
- `SECURITY-SNDL.md`: store-now-decrypt-later risk inventory, operational requirements, and PQC migration plan.
- `Cargo.toml` / `Cargo.lock`: Rust dependency and lockfile inventory.
- `Makefile`: build/install entrypoints and packaging install behavior.
- `examples/*.toml`: sample runtime configuration.
- `tools/cssh-keyscan`: helper for building target host trust entries.
- `.forgejo/workflows/build.yml` and `ci/`: Forgejo CI for Linux amd64 or arm64 packaging plus native FreeBSD amd64 packaging and native FreeBSD aarch64 cross-packaging helpers. The aarch64 FreeBSD path uses the packaged `aarch64` sysroot and a nightly `build-std` cross-build. Release helpers stage validated package artifacts on a draft Forgejo release, then the final publish helper re-downloads those staged attachments into a fresh workspace, writes `sha256sums`, and publishes one Forgejo release after all package jobs succeed. Failures ship filtered logs to the `CI.md` ingestion endpoint, and the release publication path records the exact failing command.
- `ci/release-version.sh` is the canonical release-version gate for the Forgejo pipeline. It logs the pushed tag and `Cargo.toml` version, requires `v<version>` or `V<version>` tags, and fails the packaging or publish path before artifact staging when those values drift.
- `packaging/`: FreeBSD rc and systemd service packaging.
- `Dockerfile`, `compose.yaml`, `.dockerignore`, and `container/`: container build, runtime, and example deployment artifacts.
- `container.md`: container operations guide for Docker and Podman deployments.
- `ACCESS.md`: intentionally redacted placeholder for external access notes; live inventory must stay outside source control.

## 2. Process startup flow

Entry path in `src/main.rs`:

1. Initialize `tracing_subscriber`.
   - Log filtering is driven by `CENTRALSSH_LOG` first, then `RUST_LOG`, defaulting to `info`.
   - Log formatting is driven by `CENTRALSSH_LOG_FORMAT`; if `JOURNAL_STREAM` is present, the default switches to a journald-friendly compact format on stderr.
2. Parse CLI flags and env-backed overrides with `clap`.
3. Load the seed config first so `settings` can influence downstream path resolution.
4. Resolve effective runtime paths with `config::resolve_paths`.
5. Ensure the outbound key root directory exists.
6. Load validated config state into `ConfigStore`.
7. Construct `AuthEngine`, `AuditLogger`, and `AbuseTracker`.
8. Build shared `AppState`.
9. Install a `SIGHUP` notifier and spawn the reload loop.
10. Run bootstrap:
   - migrate plaintext bootstrap passwords to Argon2id
   - create any missing outbound user key directories and keypairs
11. Derive the gateway host key path from the config directory as `<config_dir>/host_ed25519`.
12. Probe-bind the requested listen address once before starting the SSH server.
13. Start the russh server with keyboard-interactive auth only.

The CLI currently exposes:

- `--listen`
- `--config`
- `--servers`
- `--known-hosts`
- `--user-key-root`
- `--audit-log`
- `--whitelist`
- `--per-user-per-server`
- `--enforce-strict-security`

Matching environment variables are the `CENTRALSSH_*` names declared on the CLI flags, except key layout uses `PER_USER_PER_SERVER`.

## 3. Shared runtime state

`AppState` in `src/app.rs` is the top-level dependency bundle passed into SSH handlers:

- `config_store: ConfigStore`
- `auth: AuthEngine`
- `audit: AuditLogger`
- `abuse: AbuseTracker`
- `strict_security: bool`
- `reload_notify: Arc<Notify>`

`AppState::bootstrap()` does only two things:

1. `ConfigStore::migrate_bootstrap_passwords()`
2. `keys::ensure_private_keys_for_config_users()`

That means bootstrap is intentionally idempotent and bounded to credential migration plus key material creation.

## 4. Configuration system

Current config format is TOML, not the JSON structure described by the long-form design spec.

Primary structs in `src/config/mod.rs`:

- `ConfigFile`
- `SettingsConfig`
- `KexPolicyConfig`
- `AuthorizationPolicyConfig`
- `EffectiveAuthorizationPolicy`
- `UserRecord`
- `ServersFile`
- `EffectivePaths`
- `RuntimeState`
- `ConfigStore`

### 4.1 Path resolution

`resolve_paths()` chooses effective paths in this order:

1. explicit CLI / env override passed into `main.rs`
2. selected `settings` values from `config.toml`
3. compiled defaults

Important exception:

- `config.toml` itself must be found before settings can be read, so its path cannot depend on settings inside the file.
- `servers.toml` has no `settings` override inside `config.toml`; it is controlled by CLI/env or the compiled default.
- the gateway host key is not separately configurable; it is derived from the config directory as `<config_dir>/host_ed25519`.
- `drop_to_menu` and `hide_proxy_ip` are runtime settings and can be overridden by CLI/env or FreeBSD rc.conf the same way `per_user_per_server` can.
- the FreeBSD rc script forwards `centralssh_per_user_per_server` to `--per-user-per-server`; per-user `allow_*` values still come only from `config.toml`

### 4.2 Load and reload

`ConfigStore::load()` and `ConfigStore::reload()` both:

1. read `config.toml`
2. read `servers.toml`
3. apply runtime overrides back into the in-memory config
4. validate filesystem security rules
5. validate config semantics

`settings.hide_proxy_ip` is presentation-only: it changes the authenticated server-selection menu so users see only logical server names instead of `name (host)` entries.
6. install the result as a new immutable snapshot

Reload is all-or-nothing. Invalid reload input does not replace the previous active state.

### 4.3 Config validation

`validate_semantics()` enforces:

- at least one user
- at least one server
- valid server identifiers
- valid host/IP-like target strings
- unique usernames
- valid username syntax `[a-zA-Z0-9._-]`, length `1..64`
- valid password field shape
- valid TOTP secret parseability
- at least one allowed server per user
- every allowed server must exist in `servers.toml`
- unambiguous authorization policy mode selection
- user-level `allow_*` fields only when `settings.per_user_per_server = false`
- `[server.user]` authorization policy tables only when `settings.per_user_per_server = true`
- policy-table server and user references must exist and match `allowed_servers`
- configured frontend KEX names must be supported by the pinned SSH library stack
- fail2ban config must be parseable if present
- password policy minimum must be `<= 256`

Bootstrap password fields are allowed only when:

- the field is non-empty
- length is `<= 256`
- `must_change_password = true`
- the value is not one of the documented placeholder passwords

Otherwise the password must already be an Argon2id string.

The packaged example intentionally uses a rejected placeholder so operators must replace it before startup. Previously documented sample values such as `TemporaryPassword123!` and `AnotherTempPass123!` are also rejected.

Authorization policy defaults are explicit in code:

- `allow_local_forwarding = false`
- `allow_remote_forwarding = false`
- `allow_sftp = true`
- `allow_scp = true`

`resolve_effective_authorization_policy()` computes one deterministic policy for the authenticated `username + selected target` pair. The implementation does not merge user-level and per-server policy sources.

### 4.4 Atomic mutation

Credential changes do not rewrite config in place.

`ConfigStore::migrate_bootstrap_passwords()` and `ConfigStore::update_user_credentials()`:

1. load `config.toml` into a `toml_edit::DocumentMut`
2. update only the matching `[[users]]` table
3. call atomic write helpers

`atomic_write_bytes()` performs:

1. temporary file creation in the same directory
2. mode `0600` on creation
3. full content write
4. `fsync` on the temp file
5. preserve owner/mode from the original file when present
6. atomic rename into place
7. parent directory `fsync`

Symlink traversal is rejected during these operations.

## 5. Security model enforced by file handling

`src/config/mod.rs`, `src/keys/mod.rs`, `src/audit/mod.rs`, and `src/ssh/mod.rs` all perform direct filesystem hardening checks.

Reusable checks include:

- `validate_path_has_no_symlinks()`
- `validate_file_security()`
- `validate_directory_security()`

Strict mode currently expects:

- config files: regular files, mode `0600`, owner uid `0`
- known_hosts: regular file, mode `0600`, owner uid `0`
- audit log: regular file, mode `0600`, owner uid `0`
- key directories: directories, mode `0700`, owner uid `0`
- outbound private keys: regular files, mode `0600`, owner uid `0`
- gateway host key: regular file, mode `0600`, owner uid `0`

Non-strict mode still rejects symlinked paths but does not require root ownership.

## 6. Authentication internals

`src/auth/mod.rs` holds the cryptographic and in-memory rate-limit pieces.

### 6.1 Password handling

- Algorithm: Argon2id
- Memory: `65536 KiB`
- Iterations: `3`
- Parallelism: `1`

The engine precomputes a dummy hash for constant-time username-miss handling.

`verify_password_constant_time()`:

1. scans all users with constant-time username comparison
2. picks the real user hash or the dummy hash
3. always runs Argon2 verification
4. succeeds only if both the hash check and real user match succeed

### 6.2 TOTP handling

- library: `totp-rs`
- digits: `6`
- period: `30s`
- skew: `1`
- secrets: random 32-byte values encoded as base32

The auth module can build an `otpauth://` URI for enrollment and validate current codes.

### 6.3 In-memory auth rate limiting

Separate from fail2ban, `AuthEngine` keeps token buckets for:

- `(ip, username)` pairs
- raw IPs

Current limits:

- user bucket capacity: `10`, refill `1 / 30s`
- IP bucket capacity: `30`, refill `1 / s`
- max tracked entries per map: `8192`
- idle prune TTL: `30m`

Rate-limit exhaustion becomes `CentralSshError::RateLimitExceeded`.

## 7. Abuse tracker internals

`src/abuse.rs` is a second layer above the auth token buckets. It is IP-centric and behaves like an internal fail2ban implementation.

Normal SSH auth-method discovery is intentionally excluded from this tracker. Probes such as `none`, opportunistic `publickey`, or disabled `password` auth are redirected toward keyboard-interactive without being counted as failed credentials.

### 7.1 Effective settings

Defaults:

- enabled: `true`
- max failures: `5`
- find time: `60s`
- first ban: `10m`
- max ban: `24h`
- backoff multiplier: `2.0`
- pre-ban delay: enabled
- delay time: `2s`
- state persistence: enabled
- state path: `/var/lib/centralssh/fail2ban_state.json`
- default whitelist: `127.0.0.1/32`, `::1/128`

Whitelist data can come from:

- `fail2ban.whitelist.ips`
- `settings.whitelist_path`

The whitelist file currently expects one literal IP per line and converts each to a single-host CIDR.

### 7.2 Stored state

Each IP entry can track:

- recent failure timestamps
- total failure count
- active ban expiry
- ban count
- last failure / success timestamps
- recent usernames
- recent target servers

### 7.3 Runtime behavior

- `check_ip()` is called before auth and can reject already-banned IPs.
- `record_failure()` updates sliding-window failures and may apply tarpit delay or create/extend a ban.
- `record_success()` clears recent failures for non-banned IPs after successful auth.
- persisted state is reloaded at startup and after config reload when enabled.

## 8. Audit logging

`src/audit/mod.rs` writes JSON Lines synchronously through a mutex-protected append file.

Each `AuditEvent` contains:

- timestamp
- event type
- request id
- remote IP and port
- username
- target server
- auth method
- result
- reason
- optional ban duration and ban-until timestamp

The logger calls `sync_data()` after every event, so audit durability is favored over throughput.

## 9. Key management

`src/keys/mod.rs` implements startup key provisioning and runtime key path resolution.

### 9.1 Path model

Private key filename is always `id_ed25519`.

When `per_user_per_server = true`:

- `<user_key_root>/<username>/<server_name>/id_ed25519`

When `per_user_per_server = false`:

- `<user_key_root>/<username>/id_ed25519`

Public keys are stored beside the private key as `id_ed25519.pub`.

The project does not commit or ship long-term private keys. Deployment-specific inventory, SSH key paths, hostnames, and topology notes belong outside source control.

### 9.2 Startup provisioning

`ensure_private_keys_for_config_users()`:

1. ensures the root key directory exists
2. ensures a directory exists for each user
3. ensures a server subdirectory exists when per-user-per-server mode is on
4. creates an Ed25519 keypair only when the private key is missing
5. leaves existing keys untouched

This is idempotent by design. Existing private keys are treated as authoritative.

### 9.3 Runtime resolution

`resolve_user_server_private_key_path()` validates username and server path components, checks the directory structure, and then validates the target private key path before use.

## 10. SSH server internals

`src/ssh/mod.rs` is the live connection state machine.

### 10.1 Transport configuration

The server uses russh with:

- keyboard-interactive auth only
- `auth_rejection_time = 3s`
- hardened KEX / cipher / MAC policy from `src/crypto_policy.rs`
- rekey limits of `512 MiB` or `30 minutes`
- compression disabled

### 10.2 Host key handling

Gateway host key path is derived as `<config_dir>/host_ed25519`.

On startup:

- if the host key exists, it is validated and mode-normalized to `0600`
- if it does not exist, a new Ed25519 key is generated
- strict mode additionally requires root ownership and exact mode `0600`

### 10.3 Per-connection handler state

`GatewayHandler` tracks:

- peer IP and port
- generated request/session id
- keyboard auth state
- authenticated username
- pending selected target
- active resolved authorization policy for the selected target
- active `ProxySession`
- whether `connection_opened` was already audited

### 10.4 Auth state machine

The main internal enum is `KeyboardAuthState`:

- `AwaitPassword`
- `AwaitExistingTotp`
- `AwaitNewPassword`
- `AwaitConfirmPassword`
- `AwaitEnrollmentTotp`
- `AwaitSelection`

The current gateway login flow is:

1. accept username from SSH transport
2. prompt for password
3. if the account already has TOTP and is not marked `must_change_password`, prompt for TOTP next
4. verify password or password+TOTP
5. if password change is required, force password replacement
6. if TOTP is missing, generate a secret, display secret plus `otpauth://` URI, and require a valid verification code
7. persist any credential changes through `ConfigStore`
8. show the allowed target menu
9. on selection, resolve the target-specific authorization policy
10. create an outbound `ProxySession`

Important implementation detail:

- existing TOTP is prompted before password verification finishes when the matched user has a TOTP secret
- if the username does not exist, the handler still moves to a TOTP prompt to reduce username enumeration signals

### 10.5 Menu and selection

`allowed_server_entries()` derives the user-visible menu from the current config snapshot.

Selection is still keyboard-interactive prompt driven. It is intentionally minimal:

- user label
- numbered server list
- selection prompt

After a valid choice, the handler stops acting like a menu flow and switches to proxy behavior.

## 11. Proxy internals

`src/ssh/proxy.rs` is where the transparent gateway behavior lives.

### 11.1 Outbound connection

`ProxySession::connect()`:

1. resolves the selected user/server private key path
2. constructs a russh client with the hardened client transport policy
3. connects to `<target-host>:22`
4. verifies the target host key with `check_known_hosts_path()` against the configured known_hosts file
5. loads the stored private key
6. authenticates to the target with SSH public key auth using the same username as the authenticated gateway user

If target auth fails, the proxy session is not created.

`tools/cssh-keyscan` helps operators populate trust entries. It accepts raw known_hosts lines and SHA256 OpenSSH fingerprints only; MD5 fingerprints are rejected rather than supported as a compatibility fallback. For destination path resolution it prefers `CENTRALSSH_KNOWN_HOSTS`, then FreeBSD `centralssh_known_hosts` via the normal `rc.conf` / `rc.conf.d` load path, then `/etc/centralssh/known_hosts`.

### 11.2 Supported forwarded features

The current proxy code explicitly supports:

- session channels
- `pty-req`
- `shell`
- `exec`
- `subsystem`
- `signal`
- `window-change`
- channel `window-adjust` flow-control handling
- `env`
- `x11-req`
- local forwarding via `direct-tcpip`
- remote forwarding via `tcpip_forward` / `cancel_tcpip_forward`
- server-initiated `forwarded-tcpip`
- server-initiated X11 channel opens

Current explicit policy rejection:

- agent forwarding requests are not relayed and are logged as failures
- `direct-tcpip` is rejected when local forwarding is disabled
- `tcpip-forward` and `cancel-tcpip-forward` are rejected when remote forwarding is disabled
- `subsystem sftp` is rejected when SFTP is disabled
- SCP-style `exec` requests are rejected when SCP is disabled

### 11.3 Session bridge structure

For session channels the proxy now splits responsibility across the `russh` server callback path and one backend read loop:

- target session -> frontend client
- frontend client -> target session requests and data are forwarded immediately from the server handler callbacks in `src/ssh/mod.rs`

The session proxy keeps a per-frontend-channel map of backend session write handles so callback-driven events can be forwarded without waiting for a synthetic frontend read loop.

Policy enforcement for session requests happens in `src/ssh/mod.rs` before the corresponding backend relay call:

- `exec_request()` runs conservative SCP detection on the exact exec payload and fails the request with normal SSH failure semantics when SCP is disabled
- `subsystem_request()` rejects `sftp` before the subsystem request is proxied when SFTP is disabled
- `channel_open_direct_tcpip()`, `tcpip_forward()`, and `cancel_tcpip_forward()` reject forwarding before any backend channel or listener is created when policy forbids it

For denied SFTP and SCP, the handler now acknowledges the request, writes stderr text in the form `<protocol>: access denied`, sends exit status `1`, and closes the channel. This avoids the stock OpenSSH `sftp` client collapsing the result into a generic `subsystem request failed` line.

These denials are post-auth authorization events. They are audited as `denied_local_forward`, `denied_remote_forward`, `denied_sftp`, or `denied_scp`, and they do not call into the pre-auth fail2ban or password/TOTP failure paths.

- `BackendSessionAction`

Backend messages are still classified into `BackendSessionAction` values and applied to the frontend, preserving SSH request semantics instead of flattening everything into one shell byte stream. When `settings.drop_to_menu=true`, only a completed interactive shell suppresses the terminal close sequence and renders the server menu back onto that same frontend channel. Stock OpenSSH `sftp` and `scp` clients exit when their subsystem or exec channel closes, so those channels close normally instead of attempting an inline gateway menu. That inline menu now consumes cursor-control escape sequences instead of echoing them back into the selection prompt, so arrow keys do not visibly move the cursor across the line.

### 11.4 Raw channel bridge structure

For `direct-tcpip`, `forwarded-tcpip`, and X11 data channels the code keeps a separate per-channel backend write-handle map and uses a simpler raw relay for backend-to-frontend traffic, so forwarding channels are not mistaken for proxied `session` channels during later callbacks:

- forward `Data`
- forward `ExtendedData`
- ignore `WindowAdjusted` because it is transport-level flow control
- forward `Eof`
- close on `Close`
- record unexpected messages as errors

### 11.5 Error handling and teardown

The proxy records the first terminal error string in `last_error`.
Normal frontend `channel_eof` / `channel_close` callbacks are treated idempotently so a clean backend-driven close does not create a false proxy failure.
Both the keyboard-interactive selection prompt and the in-channel selection menu accept `Q` to disconnect the gateway session.

On fatal relay failure it:

1. disconnects the frontend SSH connection
2. disconnects the target SSH client connection
3. logs `proxy_end` as failure

Per-channel request denials such as a rejected subsystem request are relayed as channel failure plus channel close, not escalated into a whole-connection disconnect by themselves. If the session drops cleanly, `Drop` on `ProxySession` logs `proxy_end` as success.

## 12. Reload behavior

`src/reload/mod.rs` installs a Unix `SIGHUP` listener.

`AppState::reload_on_signal_loop()`:

1. waits for the notifier
2. attempts full config reload
3. if reload succeeds, refreshes abuse-tracker settings/state
4. audits `config_reload` as success or failure

Existing sessions are not live-mutated. New sessions see the latest validated snapshot.

## 13. Crypto policy

`src/crypto_policy.rs` defines the SSH transport policy for the frontend listener and the outbound target client.

Current algorithm choices:

- frontend KEX default: `mlkem768x25519-sha256`, `curve25519-sha256`, `curve25519-sha256@libssh.org`, plus `ext-info-*` and OpenSSH strict-kex markers appended internally
- outbound client KEX default: the same ML-KEM-first ordering
- host keys: Ed25519, ECDSA P-256/P-384/P-521, RSA SHA-2
- ciphers: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`
- MACs: `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`
- compression: `none`
- rekey: `512 MiB` or `30 minutes`

`config.toml` can now carry a top-level `[kex_policy]` block with:

- `frontend_preferred`: explicit operator-controlled KEX ordering
- `frontend_require_post_quantum`: PQ-only frontend mode; classical KEX names are filtered out before the listener advertises capabilities
- `backend_preferred`: explicit operator-controlled KEX ordering for gateway-to-target SSH transport
- `backend_require_post_quantum`: outbound strict-PQ mode for gateway-to-target SSH transport

Current supported configurable frontend KEX names are:

- `mlkem768x25519-sha256`
- `curve25519-sha256`
- `curve25519-sha256@libssh.org`

Legacy SSH choices such as SHA-1 `ssh-rsa`, CBC ciphers, and classic DH groups are intentionally absent.

This is now a partial PQ-hybrid transport upgrade, not full post-quantum coverage. The frontend listener and outbound SSH client can negotiate `mlkem768x25519-sha256`, but the current `russh 0.60.2` line still does not expose `sntrup761x25519-sha512`, and SSH host/user signatures remain classical. Frontend policy-load audit is implemented, backend policy-applied audit and backend negotiated-KEX audit are implemented, and per-session frontend negotiated-KEX audit remains blocked by the current `russh` server handler API.

## 14. Error model

`src/error.rs` uses `CentralSshError` as the project-wide error type.

Main buckets:

- I/O and serialization errors
- invalid config
- security policy violations
- authentication / authorization failures
- rate limit failures
- TOTP failures
- SSH library / transport failures

Most top-level fallible paths bubble these errors directly to startup, reload, or connection handling.

## 15. Current code/spec drift worth knowing

Based on the code in this repository today:

- The implementation is already using TOML config files, not the JSON examples still described in the long-form spec.
- The proxy code supports more than shell-only sessions.
- `README.md` and `op-guide.md` now describe the transparent proxy model instead of the old shell-only assumptions.
- Agent forwarding remains intentionally disabled.
- Frontend and outbound SSH transport now support `mlkem768x25519-sha256`, but `sntrup761x25519-sha512` is still not implemented by the current SSH library stack.
- The generic prompt helpers in `src/ui/mod.rs` are no longer the center of the live SSH login path.

## 16. Practical mental model

The current program can be understood as five layers:

1. `main.rs` composes validated runtime state.
2. `ssh/mod.rs` authenticates the human and selects a target.
3. `keys/mod.rs` and `config/mod.rs` resolve trusted local material.
4. `ssh/proxy.rs` opens a second SSH connection to the target.
5. The proxy layer relays SSH channels and requests rather than exposing the gateway host.

That is the real core of the current implementation.
