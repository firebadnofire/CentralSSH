# CentralSSH

CentralSSH is a hardened, OpenSSH-compatible SSH gateway.
It is a broker, not a shell host.

Users connect with a normal SSH client, authenticate through CentralSSH (`username -> password -> TOTP`), select an approved target, and CentralSSH proxies the session to that target with a per-user key.

## Protocol Boundary

CentralSSH is strictly an SSH server.

- OpenSSH client compatible.
- No custom SSH protocol extensions.
- Accepts only standard SSH mechanisms needed for gateway flow.
- Proxies standard SSH behavior after target selection, including shell, `exec`, subsystem/SFTP, and forwarding requests.
- Relays post-selection session requests and data from the `russh` server callback path instead of depending on a gateway-side pseudo-shell.
- Treats SSH channel `window-adjust` messages as normal flow control instead of session-fatal input.
- Denies gateway-local shell, gateway-local command execution, gateway filesystem access, and agent forwarding.
- Gateway login auth is internal only (`username/password/TOTP`), not SSH public-key auth.

## What You Get

- SSH transport compatible with standard `ssh` clients.
- Internal auth flow: `username -> password -> TOTP`.
- Argon2id password hashing with automatic bootstrap migration.
- Forced first-login password change and TOTP enrollment.
- Per-user allowed-server authorization.
- Strict outbound host-key verification against known_hosts.
- Structured JSONL audit logging.
- Startup reconciliation for missing per-user outbound keys.
- Hot config reload on `SIGHUP`.
- Frontend SSH transport now prefers the OpenSSH-aligned hybrid PQ KEX `mlkem768x25519-sha256`, with explicit classical Curve25519 fallback unless PQ-only mode is enabled.
- Centralized SSH crypto policy; see `SECURITY-SNDL.md` for Store Now, Decrypt Later limits, the current `sntrup761x25519-sha512` gap, and rollout guidance.

## Install Targets and Paths

Default runtime paths:

- Config: `/etc/centralssh/config.toml`
- Servers map: `/etc/centralssh/servers.toml`
- Known hosts: `/etc/centralssh/known_hosts`
- User key root: `/var/lib/centralssh/keys`
- Audit log: `/var/log/centralssh/audit.jsonl`
- Binary: `/usr/local/sbin/centralssh`
- Helper tool: `/usr/local/bin/cssh-keyscan`
- Gateway server host key: `/etc/centralssh/host_ed25519`

## Quick Start (FreeBSD First)

1. Build and install:

```bash
cd /path/to/centralSSH
make
sudo make install
```

2. Enable and start service:

```bash
sudo sysrc centralssh_enable=YES
sudo service centralssh start
sudo service centralssh status
```

3. Populate host keys for each target server:

```bash
sudo cssh-keyscan 192.168.122.123
```

4. Connect from a client:

```bash
ssh -p 7788 <gateway-host>
```

## Linux (systemd)

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now centralssh
sudo systemctl status centralssh
```

The shipped unit writes process logs to journald and defaults to:

- `CENTRALSSH_LOG=info`
- `CENTRALSSH_LOG_FORMAT=systemd`

Useful overrides:

```bash
sudo systemctl edit centralssh
```

Example drop-in:

```ini
[Service]
Environment=CENTRALSSH_LOG=debug,centralssh=debug
Environment=CENTRALSSH_LOG_FORMAT=json
```

## Containers

The repo now ships container artifacts for Docker and Podman:

- `Dockerfile`
- `.dockerignore`
- `compose.yaml`
- `container.md`

Use [container.md](/home/william/git/CentralSSH/container.md:1) for the full container deployment guide, including bind mounts, health checks, rootless notes, and Podman compatibility guidance.
The shipped `docker-compose-example/docker-compose.yml` accepts `CENTRALSSH_PUBLISH_PORT` via .env if the host cannot spare TCP `7788`.

## FreeBSD rc.conf Overrides

Optional rc.conf keys:

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

`centralssh_per_user_per_server` controls only the key-layout and policy-resolution mode override. The actual `allow_local_forwarding`, `allow_remote_forwarding`, `allow_sftp`, and `allow_scp` values remain per-user or per-server entries in `config.toml`, not rc.conf booleans.

## Makefile Behavior

Standard pipeline:

```bash
cd /path/to/centralSSH
make
sudo make install
```

`make install`:

- Installs `centralssh` and `cssh-keyscan`.
- Creates `/etc/centralssh` layout.
- Installs example `config.toml` and `servers.toml` if missing.
- Creates `/etc/centralssh/known_hosts` if missing.
- Creates `/var/log/centralssh/audit.jsonl` if missing.
- Installs FreeBSD rc script on FreeBSD.
- Installs systemd unit on non-FreeBSD hosts.

## Forgejo CI

`.forgejo/workflows/build.yml` now runs the project-specific CentralSSH build matrix described in `CI.md` for Linux and FreeBSD only, and it triggers only on version-tag pushes.

- `linux-build-test`: locked host build plus unit tests.
- `linux-packages-amd64`: systemd tarball, `.deb`, and `.rpm`, then explicit artifact validation and Linux runtime smoke checks.
- `linux-packages-arm64`: systemd tarball, `.deb`, and `.rpm`, then explicit artifact validation.
- `freebsd-amd64`: native FreeBSD runner build that emits `.pkg` and `.tar.gz`, then installs and rc-script checks the package on the FreeBSD runner itself when non-interactive root access is available.
- `freebsd-aarch64`: native FreeBSD runner cross-build that emits `aarch64` `.pkg` and `.tar.gz` artifacts without the unstable Linux-hosted QEMU boot path. The cross path uses the FreeBSD `aarch64` sysroot plus `cargo +nightly -Z build-std`.

The workflow intentionally avoids third-party `uses:` steps. Checkout, Rust toolchain setup, packaging, and validation are all done with repository-local shell logic so Forgejo mirror assumptions do not become hidden dependencies.
When a CI step fails, the workflow now ships a filtered tail of the captured error log to the internal ingestion endpoint defined in [CI.md](/Users/william/git/CentralSSH/CI.md:87) so runner-local failures are preserved outside the ephemeral job log without flooding the endpoint with routine Cargo download chatter.

## Configuration

CentralSSH reads config from TOML files.

### `/etc/centralssh/config.toml`

Example with two users:

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
whitelist_path = "/etc/centralssh/whitelist.txt"
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

Fields:

- `users`: required non-empty array.
- `users[].name`: required, unique, `1..64`, chars `[a-zA-Z0-9._-]`.
- `users[].password`: Argon2id hash or bootstrap plaintext.
- `users[].totp_secret`: optional base32 TOTP secret.
- `users[].must_change_password`: boolean.
- `users[].allowed_servers`: required non-empty list of server names in `servers.toml`.
- `users[].allow_local_forwarding`, `users[].allow_remote_forwarding`, `users[].allow_sftp`, `users[].allow_scp`: only valid when `settings.per_user_per_server=false`.
- `settings.user_key_root`: optional path override.
- `settings.per_user_per_server`: optional bool, default `true`. When `true`, CentralSSH uses one outbound key per user and server. When `false`, it uses one outbound key per user.
- `settings.drop_to_menu`: optional bool, default `false`. When `true`, a completed interactive shell returns to the server menu on the same shell channel. `sftp` and `scp` do not support an inline post-exit gateway menu with stock OpenSSH clients, so those channels close normally. Choosing `Q` from either selection menu disconnects the SSH session instead of restarting authentication.
- `settings.hide_proxy_ip`: optional bool, default `false`. When `true`, the logged-in server-selection menu shows only logical server names and omits the configured endpoint IP or hostname from the rendered list.
- `settings.known_hosts_path`: optional path override.
- `settings.audit_log_path`: optional path override.
- `settings.whitelist_path`: optional path to a fail2ban bypass file with one IPv4 or IPv6 address per row.
- `settings.enforce_password_policy`: optional bool, default `true`.
- `settings.min_password_policy`: optional integer minimum password length, default `12`.
- The server-selection prompt accepts `Q` to quit.
- `kex_policy.frontend_preferred`: ordered frontend SSH KEX allowlist. Supported values today are `mlkem768x25519-sha256`, `curve25519-sha256`, and `curve25519-sha256@libssh.org`.
- `kex_policy.frontend_require_post_quantum`: optional bool, default `false`. When `true`, CentralSSH advertises only supported post-quantum frontend KEX algorithms and classical-only clients fail during SSH negotiation. Legacy `kex_policy.require_post_quantum` is still accepted as a compatibility alias for this frontend-only setting.
- `kex_policy.backend_preferred`: ordered gateway-to-target SSH KEX allowlist. Supported values today are the same three names as `frontend_preferred`.
- `kex_policy.backend_require_post_quantum`: optional bool, default `false`. When `true`, CentralSSH refuses to negotiate a classical-only outbound SSH transport to the selected target.
- `fail2ban.enabled`: optional bool, default `true`.
- `fail2ban.max_failures`: optional integer threshold inside the sliding window, default `5`.
- `fail2ban.find_time`: optional duration string, default `60s`.
- `fail2ban.ban_time`: optional duration string for the first ban, default `10m`.
- `fail2ban.max_ban_time`: optional duration string cap for repeated bans, default `24h`.
- `fail2ban.backoff_multiplier`: optional float, default `2.0`.
- `fail2ban.delay_before_ban`: optional bool, default `true`.
- `fail2ban.delay_time`: optional duration string, default `2s`.
- `fail2ban.persist_state`: optional bool, default `true`.
- `fail2ban.state_path`: optional path for persisted abuse state, default `/var/lib/centralssh/fail2ban_state.json`.
- `fail2ban.whitelist.ips`: optional IPv4/IPv6 CIDR list. Defaults include `127.0.0.1/32` and `::1/128`.

Authorization policy:

- CentralSSH resolves one effective post-auth policy for each `username + selected target`.
- Default values for missing policy keys are explicit and deterministic:
  `allow_local_forwarding=false`, `allow_remote_forwarding=false`, `allow_sftp=true`, `allow_scp=true`.
- When `settings.per_user_per_server=false`, CentralSSH reads `allow_*` fields directly from each `[[users]]` entry and rejects `[server.user]` policy tables at load or reload time.
- When `settings.per_user_per_server=true`, CentralSSH reads `allow_*` fields only from `[server.user]` tables such as `[git.alice]` and rejects user-level `allow_*` fields at load or reload time.
- Per-server policy tables must reference an existing server, an existing user, and a user/server pair already allowed by `users[].allowed_servers`.
- `allow_local_forwarding=false` rejects `direct-tcpip` channel opens before any backend forwarding channel is established.
- `allow_remote_forwarding=false` rejects `tcpip-forward` and `cancel-tcpip-forward` requests before any backend listener is created or touched.
- `allow_sftp=false` rejects `subsystem` requests where the subsystem name is exactly `sftp`.
- `allow_scp=false` rejects SCP-style `exec` requests after conservative command parsing detects `scp` source or sink mode flags such as `-f` or `-t`. It does not treat arbitrary `exec` requests as SCP.
- When SFTP or SCP is denied after successful authentication and target selection, CentralSSH disconnects with a user-facing message such as `SFTP: access denied` or `SCP: access denied` instead of leaving the client with only a generic channel failure.

Notes:

- Outbound target SSH username is always the authenticated CentralSSH username.
- If bootstrap plaintext passwords are present, CentralSSH hashes them with Argon2id at startup and atomically rewrites config.
- The documented placeholder password is rejected at config validation time. Replace it before starting the service.
- The frontend listener and outbound SSH client currently support `mlkem768x25519-sha256` but not `sntrup761x25519-sha512`; configuring the latter in either frontend or backend policy fails startup validation.
- `SIGHUP` reload updates auth, authorization, and abuse-control settings, but transport KEX policy is fixed for existing listener/client configs and currently requires a process restart to change the frontend offer set.
- No OpenSSH weak-crypto warning on the frontend means the client-to-gateway KEX was hybrid; it does not mean signatures, stored keys, or every outbound target session are post-quantum.
- Denied forwarding, SFTP, and SCP operations are post-auth policy denials. They are audited as `denied_*` events and do not increment password/TOTP failure counters or fail2ban bans.

## PQ Validation

For a repeatable local validation of frontend PQ negotiation and strict-mode rejection, use [tools/validate-pq-kex.sh](/Users/william/git/CentralSSH/tools/validate-pq-kex.sh:1).

Build first:

```bash
CARGO_HOME=/tmp/centralssh-cargo-home CARGO_TARGET_DIR=/tmp/centralssh-target cargo build
chmod +x tools/validate-pq-kex.sh
CENTRALSSH_BIN=/tmp/centralssh-target/debug/centralssh tools/validate-pq-kex.sh
```

## Built-In Abuse Protection

CentralSSH includes an internal fail2ban-style tracker keyed primarily by remote IP.

Behavior:

- Failures are tracked in a sliding window, not a fixed reset bucket.
- Normal SSH auth-method discovery such as `none`, `publickey`, or disabled `password` probes does not count as a failed login.
- Authenticated policy denials for forwarding, SFTP, and SCP are kept separate from brute-force tracking. They are logged, but they do not poison login-failure counters or trigger fail2ban bans.
- `max_failures` inside `find_time` creates a ban for `ban_time`.
- Repeated bans for the same IP use exponential backoff and stop growing at `max_ban_time`.
- Optional tarpitting applies `delay_time` just before the ban threshold when `delay_before_ban=true`.
- CIDR whitelist entries and `settings.whitelist_path` file entries bypass bans and failure tracking.
- If persistence is enabled, ban state is atomically saved and reloaded from `fail2ban.state_path`.

Operational notes:

- Whitelist trusted admin networks deliberately to avoid locking out operators during maintenance.
- Keep the whitelist as narrow as practical; prefer a management subnet over broad RFC1918 ranges.
- `settings.whitelist_path` expects one exact IP address per line and accepts both IPv4 and IPv6.
- The persisted state file contains timestamps, IPs, usernames, target names, and ban metadata only. It does not contain passwords or TOTP material.

### `/etc/centralssh/servers.toml`

```toml
[servers]
git = "192.168.86.44"
httpd = "192.168.86.41"
dns = "192.168.86.53"
```

Rules:

- User `allowed_servers` entries must exactly match keys in this file.
- Values are target host/IP strings used for outbound SSH.

## Auth and Session Flow

1. Client connects to CentralSSH SSH port (default `7788`).
2. CentralSSH prompts for `Username`.
3. CentralSSH prompts for `Password`.
4. Only after password success, CentralSSH prompts for `TOTP Code`.
5. If password change is required, user must change password.
6. If TOTP secret is missing, user must complete TOTP enrollment.
7. User sees menu of allowed servers.
8. User selects a server.
9. CentralSSH opens outbound SSH session to `<target>:22`.
10. On proxy session exit, user returns to gateway menu.

## Password and TOTP Lifecycle

- Password hashing algorithm: Argon2id.
- Bootstrap plaintext is migrated to Argon2id on startup.
- First-login password change enforced via `must_change_password`.
- TOTP uses RFC6238 semantics with 30s step and drift tolerance.
- TOTP secrets are base32 and never logged.

### How to set user passwords

Supported approaches:

- Recommended bootstrap flow: set a temporary plaintext in `config.toml` and `must_change_password=true`; CentralSSH migrates it to Argon2id at startup.
- Pre-hash offline and place Argon2id string directly in `users[].password`.

## Per-User Outbound Keys

Outbound private key path pattern:

- Default: `<user_key_root>/<username>/<server>/id_ed25519`
- With `PER_USER_PER_SERVER=false`: `<user_key_root>/<username>/id_ed25519`

Behavior:

- On startup, CentralSSH reconciles configured users and allowed servers.
- Missing user directories, server directories when enabled, and `id_ed25519` files are created automatically.
- Existing keys are not overwritten.
- Keys are for outbound proxy auth only, not gateway login.

## Host Key Management (`cssh-keyscan`)

`cssh-keyscan` fetches target host keys and updates CentralSSH known_hosts.

Path resolution:

- `CENTRALSSH_KNOWN_HOSTS` overrides everything.
- On FreeBSD, if that env var is unset, the tool follows `centralssh_known_hosts` from the same `rc.conf` / `rc.conf.d` flow as the service script.
- Otherwise it falls back to `/etc/centralssh/known_hosts`.

Basic usage:

```bash
sudo cssh-keyscan <server IP or domain>
```

Scriptable verified usage with expected key material:

```bash
sudo cssh-keyscan 192.168.122.123 'AAAAC3NzaC1lZDI1NTE5AAAAIHiKldTfYnX3R0tRkMA6Xy1z9NJ+IGp8H7wQy2kCoGM/'
sudo cssh-keyscan 192.168.122.123 'ssh-ed25519 SHA256:FXTNTbOFUWoYI7C4ND351UCvqSY8fhafJsjqqxInbUo'
```

Accepted expected-key formats:

- `<base64-key-blob>`
- `<algorithm> <base64-key-blob>`
- `SHA256:<fingerprint>`
- `<algorithm> SHA256:<fingerprint>`

Security behavior:

- New host without expected key: interactive TOFU prompt.
- New host with expected key: requires at least one scanned key to match; TOFU prompt skipped.
- New host with key overlap: TOFU output shows overlapping hostnames.
- Existing host with any newly presented key: hard fail; no file modification.
- MD5 fingerprints are not accepted.

## File Ownership and Modes (Production)

Required for strict mode (`--enforce-strict-security true`, default):

- `/etc/centralssh/config.toml`: owner `root`, mode `0600`
- `/etc/centralssh/servers.toml`: owner `root`, mode `0600`
- `/etc/centralssh/known_hosts`: owner `root`, mode `0600`
- `/var/lib/centralssh/keys`: owner `root`, mode `0700`
- `/var/log/centralssh/audit.jsonl`: owner `root`, mode `0600`

## Post-Install Validation Checklist

Run these checks after installation:

```bash
sudo ls -ld /etc/centralssh /var/lib/centralssh/keys /var/log/centralssh
sudo ls -l /etc/centralssh/config.toml /etc/centralssh/servers.toml /etc/centralssh/known_hosts /etc/centralssh/host_ed25519 /var/log/centralssh/audit.jsonl
sudo service centralssh status || sudo systemctl status centralssh
```

Expected posture:

- Sensitive files are mode `0600`.
- User key root directory is mode `0700`.
- Ownership is root in strict production mode.

## CLI and Environment Overrides

Show help:

```bash
/usr/local/sbin/centralssh --help
```

Run manually:

```bash
/usr/local/sbin/centralssh \
  --listen 0.0.0.0:7788 \
  --config /etc/centralssh/config.toml \
  --servers /etc/centralssh/servers.toml \
  --known-hosts /etc/centralssh/known_hosts \
  --user-key-root /var/lib/centralssh/keys \
  --audit-log /var/log/centralssh/audit.jsonl
```

Flags:

- `--listen`
- `--config`
- `--servers`
- `--known-hosts`
- `--user-key-root`
- `--per-user-per-server`
- `--audit-log`
- `--enforce-strict-security` (default `true`)

Environment variables:

- `CENTRALSSH_LISTEN`
- `CENTRALSSH_CONFIG`
- `CENTRALSSH_SERVERS`
- `CENTRALSSH_KNOWN_HOSTS`
- `CENTRALSSH_USER_KEY_ROOT`
- `PER_USER_PER_SERVER`
- `CENTRALSSH_AUDIT_LOG`
- `CENTRALSSH_ENFORCE_STRICT_SECURITY`

## Reload and Operations

### FreeBSD service commands

```bash
sudo service centralssh start
sudo service centralssh stop
sudo service centralssh restart
sudo service centralssh status
```

### systemd commands

```bash
sudo systemctl start centralssh
sudo systemctl stop centralssh
sudo systemctl restart centralssh
sudo systemctl status centralssh
sudo journalctl -u centralssh -f
```

### Reload config without dropping active sessions

```bash
sudo kill -HUP $(pgrep -x centralssh)
```

Reload behavior:

- Valid config: applied in-memory.
- Invalid config: rejected, previous config remains active.

## Auditing

Audit file:

- `/var/log/centralssh/audit.jsonl`

Event schema fields:

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

Representative events:

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

Example JSONL record:

```json
{"timestamp":"2026-05-02T20:00:00Z","event_type":"ban_created","request_id":"c7b2d8d7-66bc-4b68-a4d1-d7c0a0f4a7d9","remote_ip":"203.0.113.44","remote_port":51422,"username":"alice","target_server":null,"auth_method":"keyboard_interactive","result":"banned","reason":"fail2ban threshold reached","ban_duration_seconds":600,"ban_until":"2026-05-02T20:10:00Z"}
```

Secrets are not logged.

## Troubleshooting

### `centralssh error: I/O error: No such file or directory (os error 2)`

Missing one or more required paths.

Check:

- `/etc/centralssh/config.toml`
- `/etc/centralssh/servers.toml`
- `/etc/centralssh/known_hosts`
- `/var/log/centralssh/audit.jsonl`

Fix:

```bash
sudo make install
```

### `make install` fails under `sudo` with `cargo: No such file or directory`

Cause: root shell PATH does not include cargo.

Fix:

- Build as normal user first: `make`
- Install as root after build: `sudo make install`

### `install ... Operation not permitted` or `Permission denied`

Cause: writing into `/usr/local` without privileges.

Fix:

- Use `sudo make install`.

### Service restart reports stale pid or "already running"

Fix:

```bash
sudo service centralssh stop
sudo service centralssh start
sudo service centralssh status
```

### `invalid configuration: user '<name>' references unknown server '<server>'`

Cause: `allowed_servers` entry does not exactly match any key in `servers.toml`.

Fix:

- Correct spelling/case in `allowed_servers`.
- Ensure matching server key exists in `/etc/centralssh/servers.toml`.

### Host key verification failures when selecting a server

Cause: target host key missing or changed in known_hosts.

Fix:

- Verify target identity out-of-band.
- Update `/etc/centralssh/known_hosts` via `cssh-keyscan`.
- Retry connection.

### Non-interactive `cssh-keyscan` fails with TOFU-required message

Cause: new host and no expected key argument in a non-TTY context.

Fix:

- Provide expected key argument for scriptable mode.
- Or run interactively and confirm TOFU prompt.

## Development Mode

For local/dev-only runs where production file ownership/modes are not available:

```bash
mkdir -p ./tmp/users
cp examples/config.toml ./tmp/config.toml
cp examples/servers.toml ./tmp/servers.toml
touch ./tmp/known_hosts ./tmp/audit.jsonl

cargo run -- \
  --config ./tmp/config.toml \
  --servers ./tmp/servers.toml \
  --known-hosts ./tmp/known_hosts \
  --user-key-root ./tmp/users \
  --audit-log ./tmp/audit.jsonl
```

Disable strict-security checks for that run with:

```bash
CENTRALSSH_ENFORCE_STRICT_SECURITY=false cargo run -- \
  --config ./tmp/config.toml \
  --servers ./tmp/servers.toml \
  --known-hosts ./tmp/known_hosts \
  --user-key-root ./tmp/users \
  --audit-log ./tmp/audit.jsonl
```

Do not use this mode in production.

## Connect from Clients

```bash
ssh -p 7788 <gateway-host>
```

OpenSSH client options like `-J`/ProxyJump work as normal when targeting CentralSSH.

## License

See `LICENSE`.
