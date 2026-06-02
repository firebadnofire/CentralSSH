# CentralSSH Linux systemd binary release

This archive contains a prebuilt `centralssh` Linux binary, the `cssh-keyscan`
helper, default configuration files, and the `systemd` unit for CentralSSH.

## Install

Extract the archive, then run:

```sh
cd centralssh
sudo make install
```

The install target:

- installs `centralssh` to `/usr/local/sbin`
- installs `cssh-keyscan` to `/usr/local/bin`
- creates `/etc/centralssh`
- installs `config.toml` and `servers.toml` if they are missing
- creates `/etc/centralssh/known_hosts` if it is missing
- creates `/var/log/centralssh/audit.jsonl` if it is missing
- installs the `systemd` unit at `/etc/systemd/system/centralssh.service`

## Configure and start

Review the installed configuration before starting the service:

```sh
sudo editor /etc/centralssh/config.toml
sudo systemctl daemon-reload
sudo systemctl enable --now centralssh
```

## Staged install

For packaging or inspection without changing the host system:

```sh
make install DESTDIR=/tmp/centralssh-root
```
