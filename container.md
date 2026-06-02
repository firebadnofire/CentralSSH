# CentralSSH Container Guide

This repository ships a production-oriented multi-stage container build for CentralSSH.

The container image is designed around the same runtime layout as the host install:

- `/etc/centralssh`
- `/var/lib/centralssh`
- `/var/log/centralssh`

Mount those paths from the host. Do not bake live secrets into the image.

## Image design

- Builder: Rust on Debian Bookworm
- Runtime: `debian:bookworm-slim`
- Init: `tini`
- Health check: real SSH banner probe over TCP, not a process-only check
- Logging default: stderr JSON via `CENTRALSSH_LOG_FORMAT=json`

The runtime image includes:

- `/usr/local/sbin/centralssh`
- `/usr/local/bin/cssh-keyscan`
- `/usr/local/share/centralssh/examples/config.toml`
- `/usr/local/share/centralssh/examples/servers.toml`

## Runtime security model

The default container runs as root inside the container.

That is intentional:

- strict mode requires root-owned `0600` config, trust, host-key, and audit files
- CentralSSH writes root-owned key material under `/var/lib/centralssh`
- first-start bootstrap may atomically rewrite `config.toml`

The recommended hardening posture is:

- `cap_drop: [ALL]`
- `security_opt: [no-new-privileges:true]`
- read-only root filesystem
- tmpfs for `/tmp`
- bind-mounted persistent state for `/etc/centralssh`, `/var/lib/centralssh`, and `/var/log/centralssh`

CentralSSH listens on `7788`, so no extra Linux capability is needed for the bind itself.

## Required mounted content

`/etc/centralssh/config.toml` and `/etc/centralssh/servers.toml` must exist before startup.

The entrypoint creates these if missing:

- `/etc/centralssh/known_hosts`
- `/var/log/centralssh/audit.jsonl`

The gateway host key is generated automatically at `/etc/centralssh/host_ed25519` on first start, following the normal program logic.

## Build

```bash
docker build -t centralssh:local .
```

Podman can build the same `Dockerfile` directly:

```bash
podman build -t centralssh:local .
```

## Docker run

```bash
docker run -d \
  --name centralssh \
  --restart unless-stopped \
  --publish 7788:7788 \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -e CENTRALSSH_LOG=info \
  -e CENTRALSSH_LOG_FORMAT=json \
  -v /srv/centralssh/etc:/etc/centralssh \
  -v /srv/centralssh/lib:/var/lib/centralssh \
  -v /srv/centralssh/log:/var/log/centralssh \
  centralssh:local
```

## Compose

`compose.yaml` in the repo provides the default deployment shape.

Prepare the mounted directories first:

```bash
mkdir -p deploy/etc-centralssh deploy/var-lib-centralssh deploy/var-log-centralssh
chmod 700 deploy/etc-centralssh deploy/var-lib-centralssh deploy/var-log-centralssh
cp examples/config.toml deploy/etc-centralssh/config.toml
cp examples/servers.toml deploy/etc-centralssh/servers.toml
chmod 600 deploy/etc-centralssh/config.toml deploy/etc-centralssh/servers.toml
```

Then:

```bash
docker compose up -d --build
```

If `7788` is already in use on the host:

```bash
CENTRALSSH_PUBLISH_PORT=17788 docker compose up -d --build
```

## Networking notes

The default compose file uses bridge networking with `7788:7788`.

That is the preferred default because it:

- keeps the container isolated from the host network namespace
- still supports inbound SSH, SFTP, SCP, and forwarding
- avoids unnecessary host-network coupling

Host networking is reasonable when:

- you need the container to originate connections from the host namespace exactly
- you want to avoid Docker bridge or firewall troubleshooting during incident response

If you choose host networking, document that decision explicitly because it expands the container’s network reach and reduces isolation.

## Logging and audit persistence

Normal process logs go to stderr and integrate with:

- `docker logs`
- `podman logs`
- journald when the runtime forwards container logs there

Audit logs remain file-backed by design and must be persisted under `/var/log/centralssh/audit.jsonl`.

That split is intentional:

- transport and operational logs belong in container logging
- security audit history needs a durable file path under operator control

## Rootless notes

Rootless operation is not the default recommendation.

Expected tradeoffs:

- strict mode may fail if mounted files are not seen as uid `0` and mode `0600` inside the container
- bootstrap password migration requires write access to `config.toml`
- key generation and host-key persistence require writable mounts

If you run rootless, validate all of these explicitly before treating it as production-ready:

- file ownership as seen inside the container
- host-key creation
- bootstrap config rewrite
- private-key generation under `/var/lib/centralssh`

If those checks do not pass, keep strict mode enabled and run rootful with dropped capabilities instead of weakening the file-security model.

## Podman notes

The image layout avoids Docker-only runtime assumptions.

Expected compatible commands:

```bash
podman build -t centralssh:local .
podman run -d --name centralssh -p 7788:7788 \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop all \
  --security-opt no-new-privileges:true \
  -v /srv/centralssh/etc:/etc/centralssh \
  -v /srv/centralssh/lib:/var/lib/centralssh \
  -v /srv/centralssh/log:/var/log/centralssh \
  centralssh:local
```

If SELinux is enforcing on the host, add the appropriate relabel suffixes such as `:Z` or `:z` to the bind mounts.

## Failure scenarios to test before production

- missing `config.toml`
- missing or mismatched target `known_hosts` entry
- wrong file modes on mounted config or key directories
- read-only `config.toml` when bootstrap password migration is still required
- persistence across container restart
- long-lived sessions and forwarding behavior through the selected runtime
