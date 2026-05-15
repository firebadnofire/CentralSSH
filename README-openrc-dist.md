# CentralSSH OpenRC binary release

This archive contains a prebuilt `centralssh` Linux binary, the `cssh-keyscan`
helper, default configuration files, and install metadata for OpenRC-based
systems.

## Install

Extract the archive, then run:

```sh
cd centralssh
sudo make install
```

The install target installs `centralssh` to `/usr/local/sbin`, installs
`cssh-keyscan` to `/usr/local/bin`, installs configuration under
`/etc/centralssh`, installs the OpenRC init script, and preserves existing
configuration and trust files.

## Configure and start

Review the installed configuration before starting the service:

```sh
sudo editor /etc/centralssh/config.toml
sudo rc-service centralssh start
```

Enable the service at boot if desired:

```sh
sudo rc-update add centralssh default
```

## Staged install

For packaging or inspection without changing the host system:

```sh
make install DESTDIR=/tmp/centralssh-root
```
