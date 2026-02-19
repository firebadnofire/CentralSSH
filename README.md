# CentralSSH

CentralSSH is a hardened, OpenSSH-compatible SSH gateway.
It is a broker, not a shell host.

Users connect with a normal SSH client, authenticate through CentralSSH (`username -> password -> TOTP`), select an approved target, and CentralSSH proxies the session to that target with a per-user key.

## Protocol Boundary

CentralSSH is strictly an SSH server.

- OpenSSH client compatible.
- No custom SSH protocol extensions.
- Accepts only standard SSH mechanisms needed for gateway flow.
- Denies non-goal requests: `exec`, `subsystem`, forwarding, and agent forwarding.
- Never grants local shell, local command execution, SFTP, or filesystem access on the gateway host.
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

## Install Targets and Paths

Default runtime paths:

- Config: `/etc/centralssh/config.json`
- Servers map: `/etc/centralssh/servers.json`
- Known hosts: `/etc/centralssh/known_hosts`
- User key root: `/etc/centralssh/users`
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

## FreeBSD rc.conf Overrides

Optional rc.conf keys:

```conf
centralssh_enable="YES"
centralssh_listen="0.0.0.0:7788"
centralssh_config="/etc/centralssh/config.json"
centralssh_servers="/etc/centralssh/servers.json"
centralssh_known_hosts="/etc/centralssh/known_hosts"
centralssh_user_key_root="/etc/centralssh/users"
centralssh_audit_log="/var/log/centralssh/audit.jsonl"
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
- Creates `/etc/centralssh` layout.
- Installs example `config.json` and `servers.json` if missing.
- Creates `/etc/centralssh/known_hosts` if missing.
- Creates `/var/log/centralssh/audit.jsonl` if missing.
- Installs FreeBSD rc script on FreeBSD.
- Installs systemd unit on non-FreeBSD hosts.

## Configuration

CentralSSH reads config from JSON files.

### `/etc/centralssh/config.json`

Example with two users:

```json
{
  "users": [
    {
      "name": "alice",
      "password": "TemporaryPassword123!",
      "totp_secret": null,
      "must_change_password": true,
      "allowed_servers": ["git", "httpd"]
    },
    {
      "name": "bob",
      "password": "AnotherTempPass123!",
      "totp_secret": null,
      "must_change_password": true,
      "allowed_servers": ["dns"]
    }
  ],
  "settings": {
    "user_key_root": "/etc/centralssh/users",
    "known_hosts_path": "/etc/centralssh/known_hosts",
    "audit_log_path": "/var/log/centralssh/audit.jsonl",
    "enforce_password_policy": true
  }
}
```

Fields:

- `users`: required non-empty array.
- `users[].name`: required, unique, `1..64`, chars `[a-zA-Z0-9._-]`.
- `users[].password`: Argon2id hash or bootstrap plaintext.
- `users[].totp_secret`: base32 TOTP secret or `null`.
- `users[].must_change_password`: boolean.
- `users[].allowed_servers`: required non-empty list of server names in `servers.json`.
- `settings.user_key_root`: optional path override.
- `settings.known_hosts_path`: optional path override.
- `settings.audit_log_path`: optional path override.
- `settings.enforce_password_policy`: optional bool, default `true`.

Notes:

- Outbound target SSH username is always the authenticated CentralSSH username.
- If bootstrap plaintext passwords are present, CentralSSH hashes them with Argon2id at startup and atomically rewrites config.

### `/etc/centralssh/servers.json`

```json
{
  "servers": {
    "git": "192.168.86.44",
    "httpd": "192.168.86.41",
    "dns": "192.168.86.53"
  }
}
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

- Recommended bootstrap flow: set a temporary plaintext in `config.json` and `must_change_password=true`; CentralSSH migrates it to Argon2id at startup.
- Pre-hash offline and place Argon2id string directly in `users[].password`.

## Per-User Outbound Keys

Outbound private key path pattern:

- `/etc/centralssh/users/<username>/id_ed25519`

Behavior:

- On startup, CentralSSH reconciles configured users.
- If user key dir/key is missing, CentralSSH creates it.
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
- `SHA256:<fingerprint>` or `MD5:<fingerprint>`
- `<algorithm> SHA256:<fingerprint>` or `<algorithm> MD5:<fingerprint>`

Security behavior:

- New host without expected key: interactive TOFU prompt.
- New host with expected key: requires at least one scanned key to match; TOFU prompt skipped.
- New host with key overlap: TOFU output shows overlapping hostnames.
- Existing host with any newly presented key: hard fail; no file modification.

## File Ownership and Modes (Production)

Required for strict mode (`--enforce-strict-security true`, default):

- `/etc/centralssh/config.json`: owner `root`, mode `0600`
- `/etc/centralssh/servers.json`: owner `root`, mode `0600`
- `/etc/centralssh/known_hosts`: owner `root`, mode `0600`
- `/etc/centralssh/users`: owner `root`, mode `0700`
- `/var/log/centralssh/audit.jsonl`: owner `root`, mode `0600`

## Post-Install Validation Checklist

Run these checks after installation:

```bash
sudo ls -ld /etc/centralssh /etc/centralssh/users /var/log/centralssh
sudo ls -l /etc/centralssh/config.json /etc/centralssh/servers.json /etc/centralssh/known_hosts /etc/centralssh/host_ed25519 /var/log/centralssh/audit.jsonl
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
  --config /etc/centralssh/config.json \
  --servers /etc/centralssh/servers.json \
  --known-hosts /etc/centralssh/known_hosts \
  --user-key-root /etc/centralssh/users \
  --audit-log /var/log/centralssh/audit.jsonl
```

Flags:

- `--listen`
- `--config`
- `--servers`
- `--known-hosts`
- `--user-key-root`
- `--audit-log`
- `--enforce-strict-security` (default `true`)

Environment variables:

- `CENTRALSSH_LISTEN`
- `CENTRALSSH_CONFIG`
- `CENTRALSSH_SERVERS`
- `CENTRALSSH_KNOWN_HOSTS`
- `CENTRALSSH_USER_KEY_ROOT`
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
- `session_id`
- `source_ip`
- `username`
- `target_server`
- `result`
- `reason_code`

Secrets are not logged.

## Troubleshooting

### `centralssh error: I/O error: No such file or directory (os error 2)`

Missing one or more required paths.

Check:

- `/etc/centralssh/config.json`
- `/etc/centralssh/servers.json`
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

Cause: `allowed_servers` entry does not exactly match any key in `servers.json`.

Fix:

- Correct spelling/case in `allowed_servers`.
- Ensure matching server key exists in `/etc/centralssh/servers.json`.

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
cp examples/config.json ./tmp/config.json
cp examples/servers.json ./tmp/servers.json
touch ./tmp/known_hosts ./tmp/audit.jsonl

cargo run -- \
  --config ./tmp/config.json \
  --servers ./tmp/servers.json \
  --known-hosts ./tmp/known_hosts \
  --user-key-root ./tmp/users \
  --audit-log ./tmp/audit.jsonl \
  --enforce-strict-security false
```

Do not use this mode in production.

## Connect from Clients

```bash
ssh -p 7788 <gateway-host>
```

OpenSSH client options like `-J`/ProxyJump work as normal when targeting CentralSSH.

## License

See `LICENSE`.
