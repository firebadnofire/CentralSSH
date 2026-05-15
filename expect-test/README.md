# Expect-tests

These tests use the `Expect` program for automated logins and file transfers during development.

All of these scripts assume the program [totp-cli](https://github.com/yitsushi/totp-cli). You can quickly install it via `go install github.com/yitsushi/totp-cli@latest`.

They also assume you use the same password between the `totp-cli` program and the login of your user, so keep that in mind.

The SFTP script now also includes an interactive tab-completion smoke test, so use a normal OpenSSH `sftp` build with line-editing support if you want that check to pass.

Don't have Go on Linux yet? Use this script: [golang.sh](https://raw.githubusercontent.com/firebadnofire/zshrc-modern/refs/heads/main/golang.sh)

Get started by copying the config:

`cp config.sample.txt config.txt && nano config.txt`
