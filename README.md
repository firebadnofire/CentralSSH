# CentralSSH

CentralSSH is an OpenSSH-compatible hardened SSH gateway for users that should not receive local UNIX accounts.

CentralSSH is a connection broker, not a shell host.
Users authenticate to CentralSSH, choose an allowed target, and CentralSSH proxies SSH to the target using per-user keys.

## Features

- OpenSSH client compatible transport
- Internal auth flow: `username -> password -> TOTP`
- Argon2id password hashing with bootstrap migration support
- Forced first-login password change and TOTP enrollment
- Per-user authorization for target servers
- Strict host-key checking for outbound proxy connections
- JSONL audit logging
- No local shell, SFTP, exec, or forwarding exposure

## Security Model

- No local shell access is ever granted.
- SSH key authentication is not used for gateway login.
- Passwords are stored as Argon2id hashes.
- TOTP secrets are stored base32-encoded and never logged.
- Config writes are atomic (temp file, fsync, rename).
- Default config and secret file permissions are strict.

## Build

```bash
cd /path/to/centralSSH
make
```

This builds `target/release/centralssh`.

## Install

Standard Unix pipeline:

```bash
cd /path/to/centralSSH
make
sudo make install
```

`make install`:

- installs binary to `/usr/local/sbin/centralssh`
- installs helper tool `/usr/local/bin/cssh-keyscan`
- creates `/etc/centralssh` layout if missing
- installs default config examples if missing
- creates `/etc/centralssh/known_hosts` if missing
- creates `/var/log/centralssh/audit.jsonl` if missing
- installs FreeBSD rc.d service or Linux systemd unit

Important: `make install` expects `target/release/centralssh` to already exist.
Run `make` first as your normal user.

## FreeBSD Setup (Primary Target)

Enable and start the RC service:

```bash
sudo sysrc centralssh_enable=YES
sudo service centralssh start
sudo service centralssh status
```

Optional rc.conf overrides:

```conf
centralssh_enable="YES"
centralssh_listen="0.0.0.0:7788"
centralssh_config="/etc/centralssh/config.json"
centralssh_servers="/etc/centralssh/servers.json"
centralssh_known_hosts="/etc/centralssh/known_hosts"
centralssh_user_key_root="/etc/centralssh/users"
centralssh_audit_log="/var/log/centralssh/audit.jsonl"
```

## Linux Setup (systemd)

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now centralssh
sudo systemctl status centralssh
```

## Configuration

CentralSSH reads from `/etc/centralssh/` by default.

### `config.json`

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

- `users`: array of user records; add one object per CentralSSH user
- `users[].name`: CentralSSH login username
- `users[].password`: Argon2 hash or bootstrap plaintext (migrated at startup)
- `users[].totp_secret`: base32 TOTP secret, or `null` to force enrollment
- `users[].must_change_password`: force password change at first successful login
- `users[].allowed_servers`: list of server names this user can access
- outbound target SSH username is always the authenticated CentralSSH username
- `settings.enforce_password_policy`: optional boolean, defaults to `true`; set `false` to disable strict password policy checks during forced password change

### `servers.json`

```json
{
  "servers": {
    "git": "192.168.86.44",
    "httpd": "192.168.86.41",
    "dns": "192.168.86.53"
  }
}
```

### `known_hosts`

`/etc/centralssh/known_hosts` must contain host keys for all target servers.
CentralSSH fails closed on missing or mismatched host keys.

## Required Paths and Permissions

Use strict ownership and modes in production:

- `/etc/centralssh/config.json` -> root-owned, `0600`
- `/etc/centralssh/servers.json` -> root-owned, `0600`
- `/etc/centralssh/known_hosts` -> root-owned, `0600`
- `/etc/centralssh/users` -> root-owned, `0700`
- `/var/log/centralssh/audit.jsonl` -> root-owned, `0600`

## User Key Provisioning

Outbound key path pattern:

- `/etc/centralssh/users/<username>/id_ed25519`

At startup, CentralSSH creates missing user directories/keys for configured users.

## Runtime Behavior

Client connection flow:

1. User connects with SSH client to CentralSSH port (default `7788`)
2. CentralSSH prompts for username
3. CentralSSH prompts for password
4. If password valid, CentralSSH prompts for TOTP
5. On success, CentralSSH shows allowed server menu
6. User selects target; CentralSSH opens proxied SSH session

## Usage Examples

Run directly:

```bash
/usr/local/sbin/centralssh \
  --listen 0.0.0.0:7788 \
  --config /etc/centralssh/config.json \
  --servers /etc/centralssh/servers.json \
  --known-hosts /etc/centralssh/known_hosts \
  --user-key-root /etc/centralssh/users \
  --audit-log /var/log/centralssh/audit.jsonl
```

Connect as user:

```bash
ssh -p 7788 gateway.example.com
```

Show CLI help:

```bash
/usr/local/sbin/centralssh --help
```

Populate known_hosts for a target:

```bash
sudo cssh-keyscan <server IP or domain>
```

Example:

```bash
sudo cssh-keyscan 192.168.122.123
```

## Troubleshooting

### `centralssh error: I/O error: No such file or directory (os error 2)`

Cause: one or more default files are missing.

Check existence of:

- `/etc/centralssh/config.json`
- `/etc/centralssh/servers.json`
- `/etc/centralssh/known_hosts`
- `/var/log/centralssh/audit.jsonl`

Re-run install to scaffold defaults:

```bash
sudo make install
```

### Users see login prompt but cannot submit input

This is usually terminal newline/control handling mismatch from older binaries.
Rebuild and reinstall latest code:

```bash
make
sudo make install
sudo service centralssh restart   # FreeBSD
# or: sudo systemctl restart centralssh
```

### Host key verification failures during server selection

- Update `/etc/centralssh/known_hosts` with correct target host keys
- Reload/restart CentralSSH

## Logging

Audit log file:

- `/var/log/centralssh/audit.jsonl`

Events include auth attempts, enrollment events, selections, and proxy outcomes.
Sensitive secrets are not logged.
