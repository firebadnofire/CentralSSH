# secure-dns-proxy binary release

This archive contains a prebuilt `secure-dns-proxy` Linux binary, default
configuration files, and install metadata for systemd-based systems.

## Install

Extract the archive, then run:

```sh
cd secure-dns-proxy
sudo make install
```

The install target creates a dedicated `secure-dns-proxy` system user and group,
installs the binary to `/usr/local/bin`, installs configuration under
`/etc/secure-dns-proxy`, installs the systemd unit, and installs the sysctl
drop-in used for UDP buffer sizing.

An existing `/etc/secure-dns-proxy/config.toml` is preserved.

## Configure and start

Review the installed configuration before starting the service:

```sh
sudo editor /etc/secure-dns-proxy/config.toml
sudo systemctl daemon-reload
sudo systemctl enable --now secure-dns-proxy
```

## Staged install

For packaging or inspection without changing the host system:

```sh
make install DESTDIR=/tmp/secure-dns-proxy-root
```
