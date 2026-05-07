# CentralSSH E2E Test Harness

This directory contains the shell and `expect` harness for realistic end-to-end CentralSSH validation against real OpenSSH clients and real target `sshd` instances.

The harness is designed for the FreeBSD host plus jail topology described in [ACCESS.md](/Users/william/git/CentralSSH/ACCESS.md), but it is profile-driven and can be reused for other environments with a new profile file.

## Scope

The main runner is [run_freebsd_lab.sh](/Users/william/git/CentralSSH/tests/e2e/run_freebsd_lab.sh). It covers:

- keyboard-interactive gateway auth
- forced password change and TOTP enrollment
- target selection and authorization
- interactive shell and PTY exercise
- `ssh host command`
- `scp` and `sftp`
- `direct-tcpip`
- local and remote forwarding
- long-lived command streams
- reload and abuse handling
- PTY transcript capture
- multiplexing and low rekey-limit exercise
- degraded-network hooks
- audit and resource snapshots

Some stages are capability-gated and will record `skip` when the selected lab does not provide the required tool or topology.

## Layout

- [run_freebsd_lab.sh](/Users/william/git/CentralSSH/tests/e2e/run_freebsd_lab.sh): main entrypoint
- [profiles/](/Users/william/git/CentralSSH/tests/e2e/profiles): environment-specific profile files
- [lib/](/Users/william/git/CentralSSH/tests/e2e/lib): shared profile, capability, reset, PTY, resource, and impairment helpers
- [stages/](/Users/william/git/CentralSSH/tests/e2e/stages): stage implementations used by `smoke` and `full`
- [gateway_flow.exp](/Users/william/git/CentralSSH/tests/e2e/gateway_flow.exp): interactive gateway flow driver
- [expect/gateway_flow.exp](/Users/william/git/CentralSSH/tests/e2e/expect/gateway_flow.exp): wrapper path for stage use
- [freebsd_askpass_exec.sh](/Users/william/git/CentralSSH/tests/e2e/freebsd_askpass_exec.sh): targeted non-interactive exec helper
- [fixtures/](/Users/william/git/CentralSSH/tests/e2e/fixtures): static test inputs
- [artifacts/](/Users/william/git/CentralSSH/tests/e2e/artifacts): per-run output trees

## Requirements

Local machine requirements:

- `ssh`
- `scp`
- `sftp`
- `expect`
- `python3`
- `argon2`
- `tar`
- `nc`

Remote FreeBSD host requirements depend on the selected profile. The harness probes and records:

- `cargo` availability on host and jail
- `ipfw` and `pfctl`
- PTY tools such as `vi`, `vim`, `less`, `top`, and `script`
- resource tools such as `procstat` and `vmstat`

If the remote host does not have `cargo`, the runner falls back to the newest previously captured `centralssh.freebsd` seed binary under [artifacts/](/Users/william/git/CentralSSH/tests/e2e/artifacts). If neither is available, bootstrap fails loudly.

## Profiles

The runner loads a profile in this order:

1. `CENTRALSSH_PROFILE_FILE=/absolute/path/to/profile.env`
2. `CENTRALSSH_E2E_ENV_FILE=/absolute/path/to/profile.env`
3. `CENTRALSSH_PROFILE=<name>` which resolves to `tests/e2e/profiles/<name>.env`
4. default profile [freebsd-host-jail-141-151.env](/Users/william/git/CentralSSH/tests/e2e/profiles/freebsd-host-jail-141-151.env)

Current repo profiles:

- [access-md-home-195-hostonly.env](/Users/william/git/CentralSSH/tests/e2e/profiles/access-md-home-195-hostonly.env): current documented host-only lab on `192.168.122.195`, user launch mode, single target account
- [access-md-home-195.env.example](/Users/william/git/CentralSSH/tests/e2e/profiles/access-md-home-195.env.example): template for the current `ACCESS.md` host plus jail path
- [freebsd-host-jail-141-151.env](/Users/william/git/CentralSSH/tests/e2e/profiles/freebsd-host-jail-141-151.env): older lab profile retained for reproducibility

For the current documented access path, start from [access-md-home-195.env.example](/Users/william/git/CentralSSH/tests/e2e/profiles/access-md-home-195.env.example), copy it outside the repo if needed, and fill in the runtime details that are still environment-specific.

## Control-plane security note

The harness uses `StrictHostKeyChecking=no` and `UserKnownHostsFile=/dev/null` for the control-plane SSH hops it uses to reach the FreeBSD host and optional jail. That exception is limited to test orchestration.

It does **not** change CentralSSH runtime target verification. The gateway-known-hosts file written into the lab config is still used to verify outbound target host keys.

## Actions

Run from the repository root:

```sh
tests/e2e/run_freebsd_lab.sh preflight
tests/e2e/run_freebsd_lab.sh bootstrap
tests/e2e/run_freebsd_lab.sh smoke
tests/e2e/run_freebsd_lab.sh full
```

Supported actions:

- `preflight`: load profile, validate required variables, probe local and remote capabilities, record initial resource snapshots
- `bootstrap`: preflight, environment validation, reset, repo sync, host build or seed-binary staging, target-user setup, lab config write, gateway start
- `smoke`: bootstrap plus auth and non-interactive coverage
- `full`: full staged suite
- `reset`: run the configured reset mode only
- `full-reset`
- `lab-reset`
- `minimal-clean`
- `preserve-artifacts`

`smoke` runs:

1. profile and capability preflight
2. connectivity validation
3. reset
4. build and bootstrap
5. auth and selection
6. non-interactive coverage

`full` adds:

1. interactive shell and PTY checks
2. forwarding and long-lived sessions
3. PTY torture capture
4. multiplexing and low rekey-limit exercise
5. degraded-network stage
6. forwarding stress
7. reload, abuse, and crash/restart stages
8. audit/resource review
9. client-matrix summary

## Reset modes

You can either call the reset mode directly as the action or use `reset` with `CENTRALSSH_RESET_MODE`.

Examples:

```sh
CENTRALSSH_PROFILE_FILE=/absolute/path/profile.env \
CENTRALSSH_RESET_MODE=lab-reset \
tests/e2e/run_freebsd_lab.sh reset

CENTRALSSH_PROFILE_FILE=/absolute/path/profile.env \
tests/e2e/run_freebsd_lab.sh minimal-clean
```

Behavior:

- `full-reset`: remove and recreate the remote lab root
- `lab-reset`: clear keys, audit log, fail2ban state, and prior gateway logs inside the lab root
- `minimal-clean`: stop the gateway and clear transient logs and ban state
- `preserve-artifacts`: no remote cleanup; only keep current artifact handling

All reset paths are intended to be rerunnable. If a reset fails, stop and inspect the stage artifacts before retrying.

## Typical usage

Host-only current `ACCESS.md` path:

```sh
CENTRALSSH_PROFILE=access-md-home-195-hostonly \
CENTRALSSH_JUMP_KEY=/Users/william/.ssh/cgpt/cgpt \
tests/e2e/run_freebsd_lab.sh smoke
```

Current host-plus-jail path using a custom filled profile:

```sh
CENTRALSSH_PROFILE_FILE=/absolute/path/access-md-home-195.env \
CENTRALSSH_JUMP_KEY=/Users/william/.ssh/cgpt/cgpt \
tests/e2e/run_freebsd_lab.sh full
```

Targeted exec-path repro using the askpass helper:

```sh
CENTRALSSH_PROFILE=access-md-home-195-hostonly \
CENTRALSSH_USER=qa_proxy \
CENTRALSSH_PASSWORD='...from generated.env...' \
CENTRALSSH_TOTP_SECRET='...from generated.env...' \
CENTRALSSH_REMOTE_COMMAND='whoami' \
tests/e2e/freebsd_askpass_exec.sh
```

## Artifacts

Every run gets a timestamped directory under [artifacts/](/Users/william/git/CentralSSH/tests/e2e/artifacts):

- `results.jsonl`: stage-by-stage pass, fail, and skip records
- `generated.env`: generated QA passwords and TOTP seeds for that run
- `00-profile/`: profile snapshot and capability probes
- per-stage directories: command outputs, logs, audit snapshots, resource snapshots, PTY transcripts, and failure evidence

Treat `generated.env` as sensitive. It contains live test credentials and TOTP seeds for the run.

Important artifact files commonly used during diagnosis:

- `*.log`: `expect`, `scp`, `sftp`, and gateway command logs
- `audit.jsonl`: copied audit trail from the remote lab
- `stdout.log` and `stderr.log`: gateway process logs from the remote runtime
- `resources-*.txt`: local and remote resource snapshots
- `network-impairment.txt`: active impairment rules for degraded-network stages
- `*.typescript` and `*.timing`: PTY capture output when `script` is available locally

## What the runner mutates

The harness creates or updates only dedicated lab state for the selected profile:

- remote lab root such as `/tmp/centralssh-qa` or `/home/cgpt/centralssh-qa`
- generated CentralSSH config, servers map, known_hosts, keys, audit log, and fail2ban state under that lab root
- QA target users in the selected host and jail profiles
- temporary forwarded listeners and local helper servers during test stages

Read the active profile before running `bootstrap`, `smoke`, or `full` so you know which host, jail, and runtime path will be touched.

## Current limitations

- The default profile still points at the older `141/151` lab. Do not rely on it unless that lab still exists.
- Some scenario assertions still contain host and jail display strings that are currently hard-coded in the `expect` driver.
- Dropbear and Plink are capability-detected but not yet wired into full client-specific workflows.
- The degraded-network stage currently prefers FreeBSD `ipfw`/dummynet and will skip if that capability is absent.

## Failure handling

The runner is intended to fail loudly. On any failure:

1. open `results.jsonl`
2. inspect the failing stage directory
3. inspect copied `audit.jsonl`, `stdout.log`, and `stderr.log`
4. inspect `resources-remote-*.txt` for leaked listeners, descriptors, or stuck processes
5. rerun the smallest relevant action or stage-driving helper after the issue is understood

Do not treat skipped stages as implicit passes. A skip means the selected lab could not prove that behavior.
