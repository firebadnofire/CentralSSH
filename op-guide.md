# CentralSSH Operator Guide

This guide is for the person who installs, configures, runs, and troubleshoots CentralSSH.
It is based on the current repository state on 2026-05-04, not just the design spec.

## 1. What CentralSSH is

CentralSSH is an SSH gateway. Users connect to the gateway with a normal SSH client, authenticate to CentralSSH itself, choose an allowed target, and then the gateway opens a second SSH connection to the selected target using gateway-managed keys.

The intended flow is:

1. Client connects to CentralSSH.
2. CentralSSH prompts for username, password, and TOTP.
3. CentralSSH enforces first-login setup if needed.
4. CentralSSH shows the list of authorized target servers.
5. The user selects a server.
6. CentralSSH connects to that server over SSH with the user's stored outbound key.
7. CentralSSH relays SSH channels and requests between client and target.

## 2. Current implementation status

The operator should know that the repo currently contains both old and new assumptions.

- The top-level spec in `AGENTS.md` requires transparent SSH proxying, including `exec`, SFTP, PTY forwarding, and forwarding support.
- The current proxy code does relay `session`, `exec`, `subsystem`, PTY, `direct-tcpip`, and remote forwarding requests.
- Session request/data forwarding happens from the `russh` server callbacks, so post-selection SSH behavior does not depend on a gateway-local shell shim.
- If `settings.drop_to_menu=true`, completed interactive shell channels return to the selection menu inline. Stock OpenSSH `sftp` and `scp` clients do not support an inline post-exit gateway menu, so those channels close normally. `Q` disconnects the SSH session from either selection menu.
- The `README.md` has been updated to match this transparent proxy model.
- Agent forwarding is still rejected by policy.

Practical conclusion: operate this build as a transparent SSH gateway in progress, not as a shell-only broker, but do not rely on the README alone for feature expectations.

Container deployment guidance now lives in [container.md](/home/william/git/CentralSSH/container.md:1). Use it together with this operator guide when running CentralSSH under Docker or Podman.

## 3. Runtime layout

CentralSSH uses a small set of files and directories:

- Main config: `/etc/centralssh/config.toml`
- Server map: `/etc/centralssh/servers.toml`
- Target host trust store: `/etc/centralssh/known_hosts`
- Gateway host key: `/etc/centralssh/host_ed25519`
- Audit log: `/var/log/centralssh/audit.jsonl`
- Binary: `/usr/local/sbin/centralssh`
- Host-key helper: `/usr/local/bin/cssh-keyscan`

The repo now standardizes on `/var/lib/centralssh/keys` as the default outbound key root.

Default key mode:

- `PER_USER_PER_SERVER=true`
- key path pattern: `<user_key_root>/<username>/<server_name>/id_ed25519`

Fallback mode:

- `PER_USER_PER_SERVER=false`
- key path pattern: `<user_key_root>/<username>/id_ed25519`

## 4. Path precedence

CentralSSH resolves its paths in this order:

1. Explicit CLI flags
2. Environment variables used by those flags
3. `settings` overrides inside `config.toml` for key root, key mode, known_hosts, and audit log
4. Compiled defaults

Important detail:

- `config.toml` itself must be found first, because the process reads it before it can use `settings` inside it.
- `servers.toml` does not have a `settings` override inside `config.toml`; use CLI or env if you want to move it.
- The gateway host key path is not separately configurable. It is always `<config directory>/host_ed25519`.

## 5. CLI and environment variables

Supported CLI flags:

- `--listen`
- `--config`
- `--servers`
- `--known-hosts`
- `--user-key-root`
- `--per-user-per-server`
- `--audit-log`
- `--enforce-strict-security`

Matching environment variables:

- `CENTRALSSH_LISTEN`
- `CENTRALSSH_CONFIG`
- `CENTRALSSH_SERVERS`
- `CENTRALSSH_KNOWN_HOSTS`
- `CENTRALSSH_USER_KEY_ROOT`
- `PER_USER_PER_SERVER`
- `CENTRALSSH_AUDIT_LOG`
- `CENTRALSSH_ENFORCE_STRICT_SECURITY`

Default listen address:

- `0.0.0.0:7788`

## 6. `config.toml`

This file defines users and a few optional runtime path settings.

Example:

```toml
[[users]]
name = "alice"
password = "REPLACE_WITH_UNIQUE_TEMPORARY_PASSWORD"
must_change_password = true
allowed_servers = ["git", "httpd"]

[[users]]
name = "bob"
password = "REPLACE_WITH_UNIQUE_TEMPORARY_PASSWORD"
must_change_password = true
allowed_servers = ["dns"]

[settings]
user_key_root = "/var/lib/centralssh/keys"
per_user_per_server = true
drop_to_menu = false
hide_proxy_ip = false
known_hosts_path = "/etc/centralssh/known_hosts"
audit_log_path = "/var/log/centralssh/audit.jsonl"
enforce_password_policy = true
min_password_policy = 12

[git.alice]
allow_local_forwarding = true
allow_remote_forwarding = false
allow_sftp = true
allow_scp = true

[httpd.alice]
allow_local_forwarding = false
allow_remote_forwarding = false
allow_sftp = true
allow_scp = false

[dns.bob]
allow_local_forwarding = false
allow_remote_forwarding = false
allow_sftp = true
allow_scp = true

[kex_policy]
frontend_preferred = [
  "mlkem768x25519-sha256",
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
]
frontend_require_post_quantum = false
backend_preferred = [
  "mlkem768x25519-sha256",
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
]
backend_require_post_quantum = false

[fail2ban]
enabled = true
max_failures = 5
find_time = "60s"
ban_time = "10m"
max_ban_time = "24h"
backoff_multiplier = 2.0
delay_before_ban = true
delay_time = "2s"
persist_state = true
state_path = "/var/lib/centralssh/fail2ban_state.json"

[fail2ban.whitelist]
ips = ["127.0.0.1/32", "::1/128", "192.168.0.0/16"]
```

If `settings.hide_proxy_ip=true`, the authenticated selection menu shows only logical server names and omits the configured endpoint IP or hostname from the displayed list.

### User fields

- `name`: required; unique; 1 to 64 characters; only `[a-zA-Z0-9._-]`
- `password`: required; either an Argon2id hash or a bootstrap plaintext password
- `totp_secret`: optional base32 TOTP secret
- `must_change_password`: boolean
- `allowed_servers`: required non-empty list of keys that must exist in `servers.toml`
- `allow_local_forwarding`, `allow_remote_forwarding`, `allow_sftp`, `allow_scp`: only valid here when `settings.per_user_per_server=false`

### Settings fields

- `user_key_root`: optional override for outbound private key root
- `per_user_per_server`: optional boolean; defaults to `true`
- `known_hosts_path`: optional override for target host trust store
- `audit_log_path`: optional override for audit log file
- `enforce_password_policy`: optional boolean; defaults to `true`
- `min_password_policy`: optional integer minimum password length; defaults to `12`

### Authorization policy fields

- CentralSSH resolves one effective policy for each authenticated `username + selected target`.
- Missing policy keys use explicit defaults:
  `allow_local_forwarding=false`, `allow_remote_forwarding=false`, `allow_sftp=true`, `allow_scp=true`.
- When `per_user_per_server=false`, CentralSSH reads `allow_*` from `[[users]]` and rejects `[server.user]` policy tables.
- When `per_user_per_server=true`, CentralSSH reads `allow_*` only from `[server.user]` tables and rejects user-level `allow_*` keys.
- Per-server policy tables must reference an existing server, an existing user, and a user/server pair already present in `allowed_servers`.
- `allow_local_forwarding=false` rejects `direct-tcpip`.
- `allow_remote_forwarding=false` rejects `tcpip-forward` and `cancel-tcpip-forward`.
- `allow_sftp=false` rejects `subsystem sftp`.
- `allow_scp=false` rejects SCP `exec` requests when the command parser detects `scp` source or sink mode flags such as `-f` or `-t`.
- Denied SFTP and SCP requests emit explicit stderr text such as `sftp: access denied` or `scp: access denied` and then close with a nonzero exit status.

### Fail2ban fields

- `enabled`: master switch for internal abuse tracking
- `max_failures`: threshold inside the sliding window before a ban is created
- `find_time`: sliding window duration
- `ban_time`: first-ban duration
- `max_ban_time`: cap for exponential backoff bans
- `backoff_multiplier`: repeated-ban growth factor
- `delay_before_ban`: enable short tarpitting before the threshold is crossed
- `delay_time`: tarpit delay duration
- `persist_state`: save and reload abuse state on restart
- `state_path`: JSON state file for persisted ban metadata
- `whitelist.ips`: CIDR ranges that bypass bans and failure tracking

### KEX policy fields

- `frontend_preferred`: ordered frontend SSH key-exchange preference list
- `frontend_require_post_quantum`: when `true`, the frontend listener advertises only supported PQ KEX algorithms
- `backend_preferred`: ordered gateway-to-target SSH key-exchange preference list
- `backend_require_post_quantum`: when `true`, the outbound gateway-to-target SSH client refuses classical-only KEX

Backward compatibility:

- `kex_policy.require_post_quantum` is still accepted as an alias for `frontend_require_post_quantum`, but new config and docs should use the explicit frontend name

Current supported `frontend_preferred` values:

- `mlkem768x25519-sha256`
- `curve25519-sha256`
- `curve25519-sha256@libssh.org`

Current non-support:

- `sntrup761x25519-sha512` is not yet exposed by the pinned `russh` dependency and CentralSSH rejects it during config validation instead of silently accepting it
- frontend per-session negotiated-KEX audit is not yet available because the current `russh` server handler API does not expose the negotiated `Names` back to CentralSSH

### Validation rules

CentralSSH rejects config at load or reload time if:

- there are no users
- usernames are duplicated or invalid
- a user has no allowed servers
- a user references an unknown server
- an Argon2id string is malformed
- a bootstrap plaintext password is empty or longer than 256 chars
- a bootstrap plaintext password is used without `must_change_password=true`
- a bootstrap plaintext password is one of the documented placeholder values
- a TOTP secret cannot be parsed into a valid runtime TOTP config

## 7. `servers.toml`

This file maps logical names shown to users onto target hostnames or IPs.

Example:

```toml
[servers]
git = "192.168.86.44"
httpd = "192.168.86.41"
dns = "192.168.86.53"
```

Rules:

- Keys are the server names users see and select.
- Values are the outbound SSH destinations used by CentralSSH.
- Server names must use the same safe character set as usernames.
- Host values must be valid IPv4, IPv6, or hostname-style strings.

## 8. Authentication model

CentralSSH only accepts keyboard-interactive SSH auth for gateway login.

- SSH public-key auth to the gateway is rejected.
- Plain SSH password auth to the gateway is rejected.
- The transport auth flow is implemented entirely through keyboard-interactive prompts.
- Normal OpenSSH auth-method discovery probes do not count toward fail2ban or password/TOTP failures.
- Authenticated policy denials for forwarding, SFTP, and SCP are logged separately and do not increment fail2ban or login-failure counters.
- Transport-level auth rejections are intentionally kept short so OpenSSH clients reach the first password prompt without a multi-second stall.

The user experience is:

1. SSH client starts a keyboard-interactive login.
2. CentralSSH prompts for password.
3. If the account has a TOTP secret, CentralSSH prompts for TOTP.
4. If `must_change_password=true`, the user must change their password before target access.
5. If `totp_secret=null`, the user must enroll in TOTP before target access.
6. The user selects an authorized target.

Terminal resize behavior:

- PTY resize events are forwarded to the selected target as `window-change` requests.
- A failed resize relay is logged, but it does not tear down the whole SSH session.

The gateway does not allow target selection before the auth and first-login flow completes.

## 9. Password handling

CentralSSH uses Argon2id for stored passwords.

Current parameters:

- memory: 65536 KiB
- iterations: 3
- parallelism: 1

Bootstrap behavior:

- If `users[].password` is not an Argon2id string, CentralSSH treats it as a bootstrap plaintext password.
- On startup, it hashes that password and atomically rewrites `config.toml`.
- It also forces `must_change_password=true`.

Operational meaning:

- You can provision accounts quickly with temporary plaintext passwords.
- After the first process start, those passwords are replaced on disk by Argon2id hashes.
- Operators should still treat any plaintext bootstrap secret as high risk until the service has started and rewritten config.
- The packaged example uses a rejected placeholder. Replace it with a unique temporary password before first start.

Password policy when enabled:

- minimum length: `settings.min_password_policy` or 12 by default
- maximum length: 256
- new password must differ from current password

## 10. TOTP handling

CentralSSH uses RFC 6238 style TOTP:

- 6 digits
- 30 second period
- skew tolerance of 1 step
- secrets are base32-encoded

If a user has no `totp_secret`, the gateway generates a new random secret and presents:

- the raw base32 secret
- an `otpauth://` enrollment URI

The user must then enter a valid current TOTP code to finish enrollment.

Important operator note:

- TOTP enrollment is persisted by rewriting `config.toml`.
- TOTP secrets are not supposed to be logged.

## 11. First-login behavior

Two independent first-login conditions can exist:

- the password must be changed
- TOTP is not enrolled yet

Current order in practice:

1. Existing password and current TOTP are verified if the user already has TOTP.
2. If `must_change_password=true`, the user is forced through password change first.
3. If no TOTP secret exists, TOTP enrollment follows.
4. Only after both are satisfied can the user select a target.

## 12. Authorization model

Authorization is simple and deny-by-default.

- Each user has an explicit `allowed_servers` list.
- The selection menu is generated from that list.
- Server names missing from `servers.toml` make config invalid.
- If the final selection cannot be resolved, the connection is denied.

There is no wildcard access model in the current config schema.

## 13. Outbound target identity

CentralSSH authenticates to the target SSH server using a private key stored on the gateway.

Current behavior:

- The outbound SSH username is always the authenticated CentralSSH username.
- There is no separate per-target login username field in config.
- That means user `alice` on the gateway will try to authenticate to the target as SSH user `alice`.

If your target systems need different login names, the current code does not provide a mapping layer for that.

## 14. Outbound private key layout

The default key resolver expects one private key per user per server:

- `<user_key_root>/<username>/<server_name>/id_ed25519`

Example:

- `/var/lib/centralssh/keys/alice/git/id_ed25519`

If `PER_USER_PER_SERVER=false`, CentralSSH falls back to one outbound key per user:

- `<user_key_root>/<username>/id_ed25519`

Validation rules:

- username and server name must use the safe component character set
- no path traversal
- no symlinks in the path
- strict mode requires real directories and files with exact permissions
- startup creates missing user directories, server directories when enabled, and `id_ed25519` files
- existing private keys are left untouched and are not overwritten

Recommended production layout:

```text
/var/lib/centralssh/keys/
  alice/
    git/
      id_ed25519
    httpd/
      id_ed25519
  bob/
    dns/
      id_ed25519
```

Recommended permissions:

- key root directory: `0700`
- user directory: `0700`
- server directory: `0700`
- private key file: `0600`
- owner: `root`

When `PER_USER_PER_SERVER=true`, use the server-specific layout above. Only use the simpler user-only layout when you explicitly disable the default mode.

## 15. Target host key verification

CentralSSH does strict outbound host-key verification against a known-hosts style file.

- Trust data lives in `known_hosts`
- The gateway checks the selected target host against that file before using the outbound key
- If the host key is missing or mismatched, the target connection fails

CentralSSH does not perform runtime blind trust.

### `cssh-keyscan`

Use the helper tool to populate or update the CentralSSH trust store:

```bash
sudo cssh-keyscan 192.168.122.123
```

You can also require expected key material:

```bash
sudo cssh-keyscan 192.168.122.123 'SHA256:...'
sudo cssh-keyscan 192.168.122.123 'ssh-ed25519 AAAA...'
```

Behavior worth knowing:

- `CENTRALSSH_KNOWN_HOSTS` has highest precedence for the destination trust file.
- On FreeBSD, if that env var is unset, the tool follows `centralssh_known_hosts` from the same `rc.conf` / `rc.conf.d` flow as the service script.
- Otherwise it writes to `/etc/centralssh/known_hosts`.
- For a new host without an expected key, the tool requires interactive TOFU confirmation.
- For a new host with expected key material, the tool auto-accepts only if at least one scanned key matches.
- If a host already exists in `known_hosts` and presents any new key, the tool refuses to update and exits with a security alert.

This is intentionally conservative. Treat that refusal as either key rotation that needs verification or a possible MITM condition.

## 16. Gateway host key

The gateway's own server host key is:

- `<config directory>/host_ed25519`

Usually:

- `/etc/centralssh/host_ed25519`

Current behavior:

- If the file does not exist, CentralSSH generates a new Ed25519 host key automatically.
- If it exists, it must be a real regular file, not a symlink.
- Strict mode requires mode `0600` and uid `0`.

Operator implication:

- The first service start can create the gateway host key for you.
- If you replace it later, preserve strict permissions and ownership.
- If you lose it, clients will see a host key change.

## 17. Audit logging

CentralSSH writes JSON Lines to the configured audit log.

Default:

- `/var/log/centralssh/audit.jsonl`

The log file is opened in append mode and each event is flushed with `sync_data()`.

Current event types include at least:

- `connection_opened`
- `connection_rejected_banned`
- `auth_attempt`
- `auth_success`
- `auth_failure`
- `unknown_username_attempt`
- `authorization_denied`
- `protocol_error`
- `ban_created`
- `ban_extended`
- `ban_expired`
- `whitelist_bypass`
- `rate_limit_delay_applied`
- `auth_password`
- `auth_totp`
- `server_selected`
- `proxy_start`
- `proxy_end`
- `config_reload`
- `agent_forward_request`

Fields currently written:

- `timestamp`
- `event_type`
- `request_id`
- `remote_ip`
- `remote_port`
- `username`
- `target_server`
- `auth_method`
- `result`
- `reason`
- `ban_duration_seconds`
- `ban_until`

Result values:

- `success`
- `failure`
- `denied`
- `banned`
- `delayed`
- `error`

The operator should monitor:

- repeated `auth_attempt` failures
- `banned` results from fail2ban
- `delayed` results from tarpitting
- `proxy_start` failures
- `config_reload` failures

Example:

```json
{"timestamp":"2026-05-02T20:00:00Z","event_type":"auth_failure","request_id":"8d46f413-e5d0-4c79-b0f1-23213efaf67b","remote_ip":"203.0.113.44","remote_port":51422,"username":"alice","target_server":null,"auth_method":"keyboard_interactive","result":"failure","reason":"authentication failed","ban_duration_seconds":null,"ban_until":null}
```

## 18. Rate limiting

CentralSSH applies token-bucket limits both per IP and per IP-plus-username.

Current values:

- per IP capacity: 30
- per IP refill: 1 token per second
- per user+IP capacity: 10
- per user+IP refill: 1 token every 30 seconds
- max tracked entries per map: 8192
- idle state cleanup TTL: 30 minutes

Operational meaning:

- bursts are allowed up to the bucket capacity
- repeated bad attempts will eventually be blocked
- hitting the maximum map size can also trigger rate-limit denial for new entries

## 19. Security mode

`--enforce-strict-security` defaults to `true`.

In strict mode, CentralSSH requires:

- config file: regular file, mode `0600`, root-owned
- servers file: regular file, mode `0600`, root-owned
- known_hosts file: regular file, mode `0600`, root-owned
- user key root: directory, mode `0700`, root-owned
- outbound key paths under that root to also satisfy strict checks
- audit log: regular file, mode `0600`, root-owned
- gateway host key: regular file, mode `0600`, root-owned

Even outside strict mode:

- symlinked path components are rejected
- parent-directory traversal is rejected
- key paths still have to be real files and directories

Non-strict mode is useful for local development, not for production deployment.

## 20. Safe writes and config mutation

When CentralSSH rewrites `config.toml`, it uses an atomic replace flow:

1. create a temp file in the same directory
2. write the full new TOML
3. `sync_all()` the temp file
4. preserve permissions and ownership where possible
5. rename over the old file
6. fsync the parent directory

This rewrite path is used for:

- bootstrap password migration
- password changes
- TOTP enrollment persistence

Operational consequence:

- If the service cannot preserve ownership during a rewrite, the write fails
- Running the service as root is the expected production model

## 21. Service management

### FreeBSD

The repo includes an rc.d script.

Common commands:

```bash
sudo sysrc centralssh_enable=YES
sudo service centralssh start
sudo service centralssh status
sudo service centralssh restart
```

Supported rc.conf knobs:

```conf
centralssh_enable="YES"
centralssh_listen="0.0.0.0:7788"
centralssh_config="/etc/centralssh/config.toml"
centralssh_servers="/etc/centralssh/servers.toml"
centralssh_known_hosts="/etc/centralssh/known_hosts"
centralssh_user_key_root="/var/lib/centralssh/keys"
centralssh_audit_log="/var/log/centralssh/audit.jsonl"
centralssh_whitelist="/etc/centralssh/whitelist.txt"
centralssh_per_user_per_server="true"
centralssh_drop_to_menu="false"
centralssh_hide_proxy_ip="false"
```

Important note:

- The rc script now defaults `centralssh_user_key_root` to `/var/lib/centralssh/keys`.
- Use `centralssh_per_user_per_server="false"` only if you intentionally want one outbound key per user and user-level `allow_*` policy fields.
- The actual `allow_local_forwarding`, `allow_remote_forwarding`, `allow_sftp`, and `allow_scp` values remain in `config.toml`; rc.conf does not provide separate global booleans for them.

### Linux

The repo includes a systemd unit:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now centralssh
sudo systemctl status centralssh
sudo journalctl -u centralssh -f
```

Important note:

- The shipped unit now passes `--user-key-root /var/lib/centralssh/keys`.
- If you want user-only keys, set `PER_USER_PER_SERVER=false` in the unit environment.
- The shipped unit also sets `CENTRALSSH_LOG=info`, `CENTRALSSH_LOG_FORMAT=systemd`, `SyslogIdentifier=centralssh`, and routes stdout/stderr directly into journald.

## 22. Installation behavior

`make install` does the following:

- installs `centralssh` to `/usr/local/sbin`
- installs `cssh-keyscan` to `/usr/local/bin`
- creates config layout under `/etc/centralssh`
- creates the log directory
- installs example `config.toml` and `servers.toml` only if missing
- creates empty `known_hosts` and `audit.jsonl` only if missing
- installs either the FreeBSD rc.d script or the systemd unit

It does not fully provision per-user per-server outbound keys for you.

## 22.1 CI pipeline

The Forgejo workflow at `.forgejo/workflows/build.yml` now follows the Linux plus FreeBSD-only matrix from `CI.md` and is triggered only by version-tag pushes.

- Linux host validation runs `cargo test --locked` and a locked release build.
- Linux packaging produces `centralssh-<version>-linux-amd64-systemd.tar.gz`, `centralssh-<version>-linux-arm64-systemd.tar.gz`, matching `.deb` packages, and matching `.rpm` packages.
- FreeBSD amd64 packaging now runs on the native `freebsd` runner and produces `centralssh-<version>-freebsd-amd64.pkg` and `centralssh-<version>-freebsd-amd64.tar.gz`. When privilege is available, the runner validates the installed package through the packaged rc script with a temporary root-owned config tree.
- FreeBSD aarch64 packaging now also runs on the native `freebsd` runner as a cross-build and produces `centralssh-<version>-freebsd-aarch64.pkg` and `centralssh-<version>-freebsd-aarch64.tar.gz`. The cross build uses the FreeBSD `aarch64` sysroot wrapper and `cargo +nightly -Z build-std`.
- Native FreeBSD jobs never block on an interactive `sudo` prompt anymore. If non-interactive root access is unavailable, the pipeline skips the privileged amd64 runtime service check instead of hanging.
- Linux and FreeBSD jobs run in parallel on their native runner classes unless an individual Linux packaging job explicitly depends on the locked host validation pass.
- Failing CI steps upload a filtered tail of their captured output to the internal HTTP ingestion endpoint from `CI.md`, which is the primary place to inspect ephemeral runner and VM-side error detail after the job exits.

## 23. Recommended production setup

1. Build and install CentralSSH.
2. Decide and standardize your outbound key root.
3. Create or verify:
   `/etc/centralssh/config.toml`
   `/etc/centralssh/servers.toml`
   `/etc/centralssh/known_hosts`
   `/var/log/centralssh/audit.jsonl`
4. Create outbound private key directories for each user/server pair.
5. Install the correct target public keys on the target systems.
6. Populate `known_hosts` with `cssh-keyscan`.
7. Start the service.
8. Verify a full login for one real user.
9. Verify target access and audit log output.

## 24. What to standardize before rollout

Before you put this into regular service, choose and document:

- the authoritative outbound key root
- whether all target systems use matching Unix usernames
- who is allowed to edit `config.toml`
- how target host key rotation is approved and executed
- how per-user outbound keys are generated, distributed, and rotated
- how audit logs are rotated and archived
- how config, key, audit-log, and fail2ban-state backups are encrypted, retained, and destroyed
- when target and gateway host keys are rotated, and how old keys are retired
- which component will be upgraded first when SSH hybrid/PQC key exchange becomes available

## 25. Operational checks

Useful checks after install:

```bash
sudo ls -ld /etc/centralssh /var/log/centralssh
sudo ls -l /etc/centralssh/config.toml /etc/centralssh/servers.toml /etc/centralssh/known_hosts /etc/centralssh/host_ed25519 /var/log/centralssh/audit.jsonl
sudo find /var/lib/centralssh/keys -type d -exec ls -ld {} \;
sudo find /var/lib/centralssh/keys -type f -exec ls -l {} \;
```

## 26. Reload behavior

CentralSSH listens for `SIGHUP` and attempts config reload.

Current semantics:

- it reloads `config.toml` and `servers.toml`
- it re-validates security checks and config semantics
- invalid new config does not replace the active in-memory config
- it writes an audit event for reload success or failure
- frontend SSH transport policy is not live-swapped on `SIGHUP`; restart the process to change advertised KEX algorithms
- backend KEX policy is read from the current config snapshot when each outbound target connection starts; existing proxied sessions keep the KEX they already negotiated

Practical usage:

```bash
sudo kill -HUP "$(pgrep -x centralssh)"
```

## 27. Connection behavior after target selection

Current code supports these behaviors through the proxy layer:

- session channels
- shell requests
- `exec` requests
- PTY allocation
- PTY resize events
- SSH channel `window-adjust` flow-control messages
- environment variable requests
- subsystem requests, including SFTP-style subsystem forwarding
- local forwarding via `direct-tcpip`
- remote forwarding via `tcpip-forward`
- X11 channel/request forwarding

Current policy enforcement can selectively deny:

- `direct-tcpip` when local forwarding is disabled
- `tcpip-forward` and `cancel-tcpip-forward` when remote forwarding is disabled
- `subsystem sftp` when SFTP is disabled
- SCP-style `exec` requests when SCP is disabled

Those denials happen after successful authentication at the SSH request layer. SFTP and SCP denials now succeed the request long enough to print a protocol-specific access-denied message before the channel exits nonzero, and all of them leave fail2ban state unchanged.

Current code rejects:

- gateway public-key auth
- gateway SSH password auth
- agent forwarding

Operator caution:

- The SSH transport policy is centralized in `src/crypto_policy.rs`.
- Frontend SSH transport now prefers `mlkem768x25519-sha256`, so current OpenSSH 9.9+ and 10.x clients should negotiate a PQ-hybrid KEX and avoid the weak-crypto warning.
- `kex_policy.frontend_require_post_quantum=true` removes classical frontend fallback entirely. Classical-only clients then fail during SSH negotiation with a no-matching-KEX error.
- `kex_policy.backend_require_post_quantum=true` is a separate control. It hard-fails outbound sessions to classical-only targets without changing frontend behavior.
- `sntrup761x25519-sha512` is still unavailable in the current `russh` line, so do not promise it operationally.
- A clean frontend handshake does not imply full PQ coverage. Host signatures, user authentication, stored key material, and any classical outbound target connection remain classical.
- See `SECURITY-SNDL.md` before using this gateway for data that must remain confidential for years.

### Reproducible validation

Local validation script:

- [tools/validate-pq-kex.sh](/Users/william/git/CentralSSH/tools/validate-pq-kex.sh:1)

Suggested usage:

```bash
CARGO_HOME=/tmp/centralssh-cargo-home CARGO_TARGET_DIR=/tmp/centralssh-target cargo build
chmod +x tools/validate-pq-kex.sh
CENTRALSSH_BIN=/tmp/centralssh-target/debug/centralssh tools/validate-pq-kex.sh
```

## 28. Troubleshooting

### Service fails immediately at startup

Check:

- file existence
- ownership
- modes
- symlink-free paths
- TOML validity
- server names referenced by users

Common causes:

- wrong mode on config or keys
- root ownership missing in strict mode
- `allowed_servers` references missing server names
- malformed Argon2id hash
- invalid TOTP secret

### User can log in to the gateway prompts but cannot reach a target

Check:

- the selected server exists in `servers.toml`
- the user's outbound private key file exists at the expected per-user per-server path
- the target host key is present in `known_hosts`
- the target accepts that user's public key
- the target account name matches the CentralSSH username

### Target connection fails with host-key errors

Check:

- whether the target is missing from `known_hosts`
- whether the target rotated keys
- whether you scanned the wrong hostname/IP variant

Use:

```bash
sudo cssh-keyscan <target>
```

If the host already exists and the tool reports a new key, stop and verify before modifying trust data.

### Client sees odd local SSH config behavior

When testing from a workstation with heavy local SSH customization, isolate the client:

```bash
ssh -F /dev/null -p 7788 <gateway-host>
sftp -F /dev/null -P 7788 <gateway-host>
```

### Reload seems ignored

Check the audit log for `config_reload` and confirm:

- the signal reached the process
- the new config passed validation

## 29. Known operator-facing inconsistencies in this repo

These are the main ones to be aware of:

- README feature claims are behind the actual proxy implementation.
- The README can still lag feature behavior if proxy support moves faster than docs.
- Key mode is now explicit: default `<root>/<user>/<server>/id_ed25519`, optional fallback `<root>/<user>/id_ed25519` with `PER_USER_PER_SERVER=false`.

If you are deploying this, resolve those inconsistencies in your own local packaging and runbook first.

## 30. Practical deployment recommendation

For a clean operator runbook, use this layout:

- `/etc/centralssh/config.toml`
- `/etc/centralssh/servers.toml`
- `/etc/centralssh/known_hosts`
- `/etc/centralssh/host_ed25519`
- `/var/lib/centralssh/keys/<user>/<server>/id_ed25519`
- `/var/log/centralssh/audit.jsonl`

Then update service configuration so the process is launched with:

- `--config /etc/centralssh/config.toml`
- `--servers /etc/centralssh/servers.toml`
- `--known-hosts /etc/centralssh/known_hosts`
- `--user-key-root /var/lib/centralssh/keys`
- `--audit-log /var/log/centralssh/audit.jsonl`

Leave `PER_USER_PER_SERVER=true` unless you are deliberately sharing one outbound key across all allowed targets for each user.

That matches the current code structure best and keeps config, trust data, secrets, and logs separated cleanly.
