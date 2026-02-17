# CentralSSH

OpenSSH-compatible hardened SSH gateway for users that should not receive local UNIX accounts.

## RC1 Behavior

- Listens on SSH port `7788` by default.
- Runs internal auth flow over SSH terminal: `username -> password -> TOTP`.
- Never grants local shell, command execution, SFTP, or forwarding access.
- Shows an authorized server menu after successful authentication.
- Proxies outbound SSH to selected target using `/etc/centralssh/users/<username>/id_ed25519`.

## Run

```bash
cargo run -- \
  --listen 0.0.0.0:7788 \
  --config /etc/centralssh/config.json \
  --servers /etc/centralssh/servers.json \
  --known-hosts /etc/centralssh/known_hosts \
  --user-key-root /etc/centralssh/users \
  --audit-log /var/log/centralssh/audit.jsonl
```
