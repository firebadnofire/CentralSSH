# CentralSSH Runbook

This document defines **repeatable, safe procedures** for operating CentralSSH and its surrounding environment (FreeBSD host + optional jails).

All actions must follow:

* ENVIRONMENT.md for topology and access
* POLICY.md for safety constraints (if present)

If a step is unclear or fails unexpectedly, **stop and reassess** before continuing.

---

# 1. Pre-flight Checks

Before performing any operation:

## 1.1 Determine connectivity path

```
ping -c 1 192.168.122.1
```

* Success → connect directly
* Failure → use jump host (`-J 192.168.86.89`)

## 1.2 Connect to host

Direct:

```
ssh cgpt@192.168.122.141
```

Via jump:

```
ssh -J 192.168.86.89 cgpt@192.168.122.141
```

---

# 2. Jail Lifecycle

## 2.1 Check if jail exists

```
bastille list
```

If `myjail2` is not listed, create it.

## 2.2 Create jail

```
bastille create myjail2 15.0-RELEASE 192.168.122.151
bastille start myjail2
```

## 2.3 Enter jail

```
ssh 192.168.122.151
```

---

# 3. Service Management

## 3.1 Check CentralSSH status (FreeBSD)

```
service centralssh status
```

## 3.2 Start service

```
service centralssh start
```

## 3.3 Restart service

```
service centralssh restart
```

## 3.4 Reload configuration

```
kill -HUP $(pgrep -x centralssh)
```

---

# 4. User Management

## 4.1 Add a new user

Edit:

```
/etc/centralssh/config.toml
```

Add:

```toml
[[users]]
name = "newuser"
password = "TEMP_PASSWORD"
must_change_password = true
allowed_servers = ["target1"]
```

Then reload config.

## 4.2 Verify user login

From client:

```
ssh -p 7788 <gateway-host>
```

Expected:

* password prompt
* TOTP flow (if applicable)
* target selection menu

---

# 5. Server (Target) Management

## 5.1 Add a new target

Edit:

```
/etc/centralssh/servers.toml
```

Example:

```toml
[servers]
newtarget = "192.168.122.200"
```

## 5.2 Assign target to user

Update user's `allowed_servers` in config.toml

## 5.3 Reload config

```
kill -HUP $(pgrep -x centralssh)
```

---

# 6. Host Key Management

## 6.1 Add target to known_hosts

```
cssh-keyscan 192.168.122.200
```

## 6.2 Verify trust

* Ensure key is written to:

```
/etc/centralssh/known_hosts
```

If mismatch occurs, **stop and verify** before proceeding.

---

# 7. Key Management

## 7.1 Verify key layout

```
/var/lib/centralssh/keys/<user>/<server>/id_ed25519
```

## 7.2 Force key creation (if missing)

Restart CentralSSH:

```
service centralssh restart
```

Startup will generate missing keys.

## 7.3 Install public key on target

```
cat id_ed25519.pub >> ~/.ssh/authorized_keys
```

(on target host)

---

# 8. Connectivity Testing

## 8.1 Basic SSH

```
ssh -F /dev/null -p 7788 <gateway-host>
```

## 8.2 SFTP

```
sftp -F /dev/null -P 7788 <gateway-host>
```

## 8.3 Port forwarding test

```
ssh -L 8080:localhost:80 -p 7788 <gateway-host>
```

---

# 9. Troubleshooting Procedures

## 9.1 Cannot connect to host

* Check ping result
* Try jump host

## 9.2 Cannot connect to jail

* Verify jail exists
* Start jail

## 9.3 Auth fails

* Check audit log:

```
/var/log/centralssh/audit.jsonl
```

* Look for:

  * rate limiting
  * ban events

## 9.4 Target connection fails

Check:

* known_hosts entry
* outbound key exists
* target accepts key

---

# 10. Safety Checklist

Before making changes:

* Confirm host vs jail context
* Confirm target system
* Confirm config paths

Never:

* Modify host from jail
* Bypass host key verification
* Expose private keys

---

# 11. Recovery

## 11.1 Unlock user (ban removal)

Restart service OR clear fail2ban state file:

```
/var/lib/centralssh/fail2ban_state.json
```

## 11.2 Restore config

* Restore from backup
* Restart service

## 11.3 Rebuild environment

* Destroy and recreate jail if needed
* Reinstall CentralSSH

---

# 12. Expected Normal Flow

1. User connects to gateway
2. Authenticates (password + TOTP)
3. Selects target
4. Gateway proxies SSH session

If behavior deviates from this, treat it as a fault condition.

