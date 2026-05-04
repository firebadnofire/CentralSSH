# Access Notes

Do not commit live access details to this repository.

This file is intentionally a placeholder. Keep real SSH key paths, usernames, hostnames, IP addresses, jail names, topology notes, and operational credentials in an approved secrets or runbook system outside source control.

Safe template:

```text
Operator workstation
  -> bastion or host: <inventory reference>
  -> jail or target: <inventory reference>

SSH key: <secret-manager reference, not a filesystem path>
Network notes: <restricted runbook reference>
Rotation owner: <team or role>
Last reviewed: <date>
```

If access details were previously committed, rotate affected credentials and review repository history exposure before treating the data as private again.
