# secure-dns-proxy OpenRC binary release

This archive contains a prebuilt `secure-dns-proxy` Linux binary, default
configuration files, and install metadata for OpenRC-based systems.

## Install

Extract the archive, then run:

```sh
cd secure-dns-proxy
sudo make install
```

The install target creates a dedicated `secure-dns-proxy` system user and group
when the host provides `useradd`/`groupadd` or BusyBox-style `adduser`/`addgroup`,
installs the binary to `/usr/local/bin`, installs configuration under
`/etc/secure-dns-proxy`, installs the OpenRC init script, and installs the sysctl
drop-in used for UDP buffer sizing.

An existing `/etc/secure-dns-proxy/config.toml` is preserved.

## Configure and start

Review the installed configuration before starting the service:

```sh
sudo editor /etc/secure-dns-proxy/config.toml
sudo rc-service secure-dns-proxy start
```

Enable the service at boot if desired:

```sh
sudo rc-update add secure-dns-proxy default
```

## Security notes

The OpenRC service runs as the dedicated `secure-dns-proxy` user. The installer
attempts to grant `CAP_NET_BIND_SERVICE` with `setcap`; if the target filesystem
or distribution does not support file capabilities, use an unprivileged DNS port
or adjust the local service policy explicitly.

## Staged install

For packaging or inspection without changing the host system:

```sh
make install DESTDIR=/tmp/secure-dns-proxy-root
```
