# Environment Overview

## Access Path

You connect in two stages:

Your machine
↓ SSH
FreeBSD host (192.168.122.141)
↓ SSH
Jail (192.168.122.151)

---

## SSH Access Notes

Always connect through the jump host.

Jump host:

```
-J 192.168.86.89
```

Example:

```
ssh -J 192.168.86.89 cgpt@192.168.122.141
```

Then connect to the jail:

```
ssh 192.168.122.151
```

---

## Host System (FreeBSD 15.0-RELEASE)

This is the control plane.

Capabilities:

* Manage jails (create, destroy, configure)
* Control networking and firewall
* Manage ZFS and storage
* Install global packages and services

---

## Jail (example: myjail2)

This jail is **illustrative**. It may not exist yet.

If it does not exist, you may need to create it using Bastille from the host.

Typical lifecycle (from host):

```
bastille create myjail2 15.0-RELEASE 192.168.122.151
bastille start myjail2
```

Then connect:

```
ssh 192.168.122.151
```

Characteristics:

* Separate userland
* Own IP address (example: 192.168.122.151)
* Isolated filesystem
* Independent services and processes

Limitations:

* Cannot manage host or other jails
* No direct kernel control
* No access to host filesystem unless explicitly mounted

---

## Mental Model

* Host = control plane
* Jail = sandboxed runtime

A jail shares the host kernel and is not a VM.

---

## Decision Rules

Use these rules when deciding where to act:

* Service deployment → jail
* Application runtime → jail
* Jail lifecycle (create/destroy/configure) → host
* Networking, firewall, storage → host

If uncertain, stop and reassess before acting.

---

## Safety Rules

* Do not attempt host-level operations from inside the jail
* Do not assume filesystem paths are shared between host and jail
* Do not treat the jail as a VM or Docker container

---

## Summary

* Host is the control layer
* Jail is the execution layer
* Access always goes through the jump host
* Always verify connectivity before proceeding

