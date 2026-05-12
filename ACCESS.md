# ACCESS.md

## Purpose

This document describes the approved access workflow and operational assumptions for the environment.

Treat all access information in this document as sensitive operational data.

---

# Testing Guidance

Docker-based testing should be preferred whenever it is reasonable and sufficient for the task.

The repository already contains Docker support for the primary application. Prefer spawning disposable containers for:

* Functional testing
* Connectivity validation
* Configuration validation
* SSH behavior testing
* Client interoperability checks
* Basic regression testing

When appropriate, testing environments may include:

* Containers running the project itself
* Generic Ubuntu containers (ubuntu:rolling)
* Generic Alpine Linux containers (alpine:latest)
* Additional lightweight Linux containers needed for interoperability testing

Avoid unnecessary VM or bare-metal usage when containerized testing provides equivalent coverage.

Use full VM, jail, or physical-system testing when:

* Kernel behavior matters
* Networking behavior requires it
* SSH edge cases cannot be reproduced in containers
* Bastille behavior is involved
* FreeBSD-specific functionality is being validated
* Performance or long-lived session behavior needs realistic system coverage

---

# Operator Access

## SSH Key

Primary SSH key:

```text
/Users/william/.ssh/cgpt/cgpt
```

Recommended permissions:

```bash
chmod 600 /Users/william/.ssh/cgpt/cgpt
```

---

# User Information

Primary SSH user:

```text
cgpt
```

---

# Reachable Systems

## Home System

Directly reachable:

```text
192.168.86.65
```

Example connection:

```bash
ssh -i /Users/william/.ssh/cgpt/cgpt cgpt@192.168.86.65
```

---

## Internal System

Reachable through SSH jump host using `-J home`:

```text
192.168.122.195
```

Example connection:

```bash
ssh -J home -i /Users/william/.ssh/cgpt/cgpt cgpt@192.168.122.195
```

Equivalent explicit jump example:

```bash
ssh -J cgpt@192.168.86.65 -i /Users/william/.ssh/cgpt/cgpt cgpt@192.168.122.195
```

---

# Privilege Escalation

`sudo` access is available.

Example:

```bash
sudo -i
```

Validate access:

```bash
sudo true
```

---

# Bastille Availability

`Bastille` is installed and available on:

```text
192.168.122.195
```

Example commands:

```bash
sudo bastille list
```

```bash
sudo bastille create testjail 15.0-RELEASE 192.168.122.210
```

```bash
sudo bastille console testjail
```

---

# Operational Notes

* Use key-based authentication only.
* Avoid copying private keys to remote systems.
* Prefer SSH jump hosts over exposing internal systems directly.
* Validate host keys before trusting newly rebuilt systems.
* Use Bastille networking carefully to avoid subnet conflicts.
* Review firewall and PF configuration before exposing jails externally.
* The host 192.168.86.65 is AARCH64. The host 192.168.122.195 is AMD64.
* It is recommended to build on the current machine, then push to 192.168.86.65. This is because they share an arch, and 192.168.86.65 has a weak CPU.

