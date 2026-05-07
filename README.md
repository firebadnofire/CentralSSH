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
- Denies gateway-local shell, gateway-local command execution, gateway filesystem access, and agent forwarding.
- Gateway login auth is internal only (`username/password/TOTP`), not SSH public-key auth.

## What You Get

- SSH transport compatible with standard `ssh` clients.
- Internal auth flow: `username -> password -> TOTP`.
- Argon2id password hashing with automatic bootstrap migration.
- Startup cryptographic readiness checks before bootstrap migration or key creation.
- Encrypted-at-rest config secrets and outbound private keys when a KEK provider is configured.
- Forced first-login password change and TOTP enrollment.
- Per-user allowed-server authorization.
- Strict outbound host-key verification against known_hosts.
- Structured JSONL audit logging.
- Startup reconciliation for missing per-user outbound keys.
- Hot config reload on `SIGHUP`.
- Centralized SSH crypto policy; see `SECURITY-SNDL.md` for Store Now, Decrypt Later limitations and migration work.

## Install Targets and Paths

Default runtime paths:

- Config: `/etc/centralssh/config.toml`
- Servers map: `/etc/centralssh/servers.toml`
- Known hosts: `/etc/centralssh/known_hosts`
- User key root: `/var/lib/centralssh/keys`
- Audit log: `/var/log/centralssh/audit.jsonl`
- Master keyset: `/etc/centralssh/master.key`
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

2. Provision the `[security]` provider and `master.key` for strict production, then enable and start service:

```bash
sudo sysrc centralssh_enable=YES
sudo service centralssh start
sudo service centralssh status
```

Production strict mode requires a configured `[security]` provider, a valid
`master.key`, encrypted config secret fields, and encrypted outbound private-key
files before startup bootstrap is allowed to mutate config or create keys.

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

## End-to-End Tests

The repository includes a profile-driven FreeBSD E2E harness under [tests/e2e/README.md](/Users/william/git/CentralSSH/tests/e2e/README.md). Use it for real gateway validation with OpenSSH clients, keyboard-interactive auth, PTY exercise, forwarding, `scp`/`sftp`, reload, and audit/resource capture.

Typical entry points:

```sh
CENTRALSSH_PROFILE=access-md-home-195-hostonly \
CENTRALSSH_JUMP_KEY=/Users/william/.ssh/cgpt/cgpt \
tests/e2e/run_freebsd_lab.sh smoke

CENTRALSSH_PROFILE_FILE=/absolute/path/profile.env \
CENTRALSSH_JUMP_KEY=/Users/william/.ssh/cgpt/cgpt \
tests/e2e/run_freebsd_lab.sh full
```

The detailed harness contract, reset modes, artifact layout, and profile guidance are documented in [tests/e2e/README.md](/Users/william/git/CentralSSH/tests/e2e/README.md).

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
centralssh_master_key="/etc/centralssh/master.key"
centralssh_whitelist="/etc/centralssh/whitelist.txt"
```

## Makefile Behavior

Standard pipeline:

```bash
cd /path/to/centralSSH
make
sudo make install
```

`make install`:

- Installs `centralssh` and `cssh-keyscan`.
- Uses `$(CARGO_TARGET_DIR)/$(PROFILE)/centralssh` for the staged binary path, so cached CI builds do not need Cargo outputs copied back into `target/release`.
- Creates `/etc/centralssh` layout.
- Installs example `config.toml` and `servers.toml` if missing.
- Creates `/etc/centralssh/known_hosts` if missing.
- Creates `/var/log/centralssh/audit.jsonl` if missing.
- Does not generate `master.key`; provision it with the chosen KEK provider before strict production startup.
- Installs FreeBSD rc script on FreeBSD.
- Installs systemd unit on non-FreeBSD hosts.

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
known_hosts_path = "/etc/centralssh/known_hosts"
audit_log_path = "/var/log/centralssh/audit.jsonl"
whitelist_path = "/etc/centralssh/whitelist.txt"
enforce_password_policy = true
min_password_policy = 12

# Production strict mode requires a real provider and encrypted secret values.
# [security]
# master_key_path = "/etc/centralssh/master.key"
# encrypted_config = true
# encrypted_keys = true
#
# [security.kek_provider]
# kind = "tpm2-command"
# command_path = "/usr/local/sbin/centralssh-tpm-unseal"
# expected_sha256 = "<64 hex chars>"

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
- `settings.user_key_root`: optional path override.
- `settings.per_user_per_server`: optional bool, default `true`. When `true`, CentralSSH uses one outbound key per user and server. When `false`, it uses one outbound key per user.
- `settings.known_hosts_path`: optional path override.
- `settings.audit_log_path`: optional path override.
- `settings.whitelist_path`: optional path to a fail2ban bypass file with one IPv4 or IPv6 address per row.
- `settings.enforce_password_policy`: optional bool, default `true`.
- `settings.min_password_policy`: optional integer minimum password length, default `12`.
- `security.master_key_path`: optional path to the structured keyset file, default `/etc/centralssh/master.key`.
- `security.encrypted_config`: encrypt `users[].password` and `users[].totp_secret` values on writes.
- `security.encrypted_keys`: encrypt outbound private-key file contents on creation.
- `security.allow_insecure_boot`: explicit emergency escape hatch; logs a critical warning every startup.
- `security.kek_provider.kind`: `tpm2-command`, `external-command`, `passphrase-env`, or non-strict-only `raw-file`.
- `security.kek_provider.command_path`: absolute provider binary path for command providers; no shell is used.
- `security.kek_provider.command_args`: optional command args; rejected unless exactly repeated in `allowed_command_args`.
- `security.kek_provider.expected_sha256`: optional SHA256 attestation hash for the provider binary.
- `security.kek_provider.env`: passphrase environment variable for `passphrase-env`.
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

Notes:

- Outbound target SSH username is always the authenticated CentralSSH username.
- If bootstrap plaintext passwords are present, CentralSSH hashes them with Argon2id at startup and atomically rewrites config only after cryptographic readiness succeeds.
- If the service cannot preserve file ownership during that rewrite, startup fails instead of silently rewriting with different custody.
- The documented placeholder password is rejected at config validation time. Replace it before starting the service.

## Built-In Abuse Protection

CentralSSH includes an internal fail2ban-style tracker keyed primarily by remote IP.

Behavior:

- Failures are tracked in a sliding window, not a fixed reset bucket.
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

## Secret Storage and `master.key`

Strict mode performs KEK/provider readiness before bootstrap. If the provider or
`master.key` fails, CentralSSH does not migrate passwords, generate outbound keys,
or rewrite config.

For `tpm2-command`, the TPM participates only in KEK custody and unseal policy.
It is not SSH transport encryption, and decrypted material still exists in
process memory after unseal.

`master.key` is TOML with this schema:

```toml
version = 1
active_key_id = "key-2026-05"
mac = "hmac-sha256:<hex>"

[[keys]]
key_id = "key-2026-05"
wrapped_key = "<hex provider-wrapped 32-byte master key>"
provider = "tpm2-command"
created_at = "2026-05-05T00:00:00Z"
```

Rules:

- `key_id` values must be unique.
- `active_key_id` must match exactly one key entry.
- The file MAC is verified with the active unwrapped key before secrets are used.
- Encrypted blobs include their `key_id`; startup rejects orphaned config key IDs.
- Command providers receive the wrapped blob on stdin and must write exactly 32 unwrapped bytes to stdout.

Encryption uses AES-256-GCM with HKDF context separation: `config/password`,
`config/totp`, and `ssh/private_key`. Rotation must keep the previous key entry
until all blobs have been rewrapped and validated.

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
- Bootstrap plaintext is migrated to Argon2id on startup after KEK/provider readiness succeeds.
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
- With `security.encrypted_keys=true`, private-key file contents are encrypted envelopes and are decrypted only for in-memory parsing at connection time.
- Keys are for outbound proxy auth only, not gateway login.

## Host Key Management (`cssh-keyscan`)

`cssh-keyscan` fetches target host keys and updates CentralSSH known_hosts.

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
- `/etc/centralssh/master.key`: owner `root`, mode `0600`
- `/var/lib/centralssh/keys`: owner `root`, mode `0700`
- `/var/log/centralssh/audit.jsonl`: owner `root`, mode `0600`

## Post-Install Validation Checklist

Run these checks after installation:

```bash
sudo ls -ld /etc/centralssh /var/lib/centralssh/keys /var/log/centralssh
sudo ls -l /etc/centralssh/config.toml /etc/centralssh/servers.toml /etc/centralssh/known_hosts /etc/centralssh/master.key /etc/centralssh/host_ed25519 /var/log/centralssh/audit.jsonl
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
  --audit-log /var/log/centralssh/audit.jsonl \
  --master-key /etc/centralssh/master.key
```

Flags:

- `--listen`
- `--config`
- `--servers`
- `--known-hosts`
- `--user-key-root`
- `--per-user-per-server`
- `--audit-log`
- `--master-key`
- `--enforce-strict-security` (default `true`)

Environment variables:

- `CENTRALSSH_LISTEN`
- `CENTRALSSH_CONFIG`
- `CENTRALSSH_SERVERS`
- `CENTRALSSH_KNOWN_HOSTS`
- `CENTRALSSH_USER_KEY_ROOT`
- `PER_USER_PER_SERVER`
- `CENTRALSSH_AUDIT_LOG`
- `CENTRALSSH_MASTER_KEY`
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
- `/etc/centralssh/master.key`
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

When non-strict mode is used without an explicit `--listen` or
`CENTRALSSH_LISTEN`, CentralSSH binds `127.0.0.1:7788` instead of exposing a
remote listener by default.

## Security Limits

This hardening protects at-rest config and outbound key files. It does not stop
RAM extraction, live process compromise, malicious provider binaries, or future
quantum attacks against today’s classical SSH transport.

## Connect from Clients

```bash
ssh -p 7788 <gateway-host>
```

OpenSSH client options like `-J`/ProxyJump work as normal when targeting CentralSSH.

## License

See `LICENSE`.
