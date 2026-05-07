#!/bin/sh
set -eu

detect_local_capabilities() {
  CENTRALSSH_CAP_SCRIPT=false
  CENTRALSSH_CAP_ASCIINEMA=false
  CENTRALSSH_CAP_DUMPTERM=false
  CENTRALSSH_CAP_OPENSSH=true
  CENTRALSSH_CAP_DROPBEAR=false
  CENTRALSSH_CAP_PUTTY=false

  command -v script >/dev/null 2>&1 && CENTRALSSH_CAP_SCRIPT=true
  command -v asciinema >/dev/null 2>&1 && CENTRALSSH_CAP_ASCIINEMA=true
  command -v infocmp >/dev/null 2>&1 && CENTRALSSH_CAP_DUMPTERM=true
  command -v dbclient >/dev/null 2>&1 && CENTRALSSH_CAP_DROPBEAR=true
  command -v plink >/dev/null 2>&1 && CENTRALSSH_CAP_PUTTY=true

  export CENTRALSSH_CAP_SCRIPT CENTRALSSH_CAP_ASCIINEMA CENTRALSSH_CAP_DUMPTERM
  export CENTRALSSH_CAP_OPENSSH CENTRALSSH_CAP_DROPBEAR CENTRALSSH_CAP_PUTTY
}

detect_remote_capabilities() {
  host_ssh "sh -lc 'command -v cargo >/dev/null 2>&1 && echo cargo_host=true || echo cargo_host=false
command -v ipfw >/dev/null 2>&1 && echo ipfw_host=true || echo ipfw_host=false
command -v pfctl >/dev/null 2>&1 && echo pfctl_host=true || echo pfctl_host=false
command -v script >/dev/null 2>&1 && echo script_host=true || echo script_host=false'" >"$CENTRALSSH_STAGE_DIR/host-capabilities.env"

  jail_ssh "sh -lc 'command -v cargo >/dev/null 2>&1 && echo cargo_jail=true || echo cargo_jail=false
command -v vim >/dev/null 2>&1 && echo vim_jail=true || echo vim_jail=false
command -v vi >/dev/null 2>&1 && echo vi_jail=true || echo vi_jail=false
command -v less >/dev/null 2>&1 && echo less_jail=true || echo less_jail=false
command -v top >/dev/null 2>&1 && echo top_jail=true || echo top_jail=false
command -v script >/dev/null 2>&1 && echo script_jail=true || echo script_jail=false
command -v procstat >/dev/null 2>&1 && echo procstat_jail=true || echo procstat_jail=false
command -v vmstat >/dev/null 2>&1 && echo vmstat_jail=true || echo vmstat_jail=false'" >"$CENTRALSSH_STAGE_DIR/jail-capabilities.env"

  # shellcheck disable=SC1090
  . "$CENTRALSSH_STAGE_DIR/host-capabilities.env"
  # shellcheck disable=SC1090
  . "$CENTRALSSH_STAGE_DIR/jail-capabilities.env"

  CENTRALSSH_CAP_IPFW_HOST=${ipfw_host:-false}
  CENTRALSSH_CAP_PFCTL_HOST=${pfctl_host:-false}
  CENTRALSSH_CAP_CARGO_HOST=${cargo_host:-false}
  CENTRALSSH_CAP_CARGO_JAIL=${cargo_jail:-false}
  CENTRALSSH_CAP_VIM_JAIL=${vim_jail:-false}
  CENTRALSSH_CAP_VI_JAIL=${vi_jail:-false}
  CENTRALSSH_CAP_LESS_JAIL=${less_jail:-false}
  CENTRALSSH_CAP_TOP_JAIL=${top_jail:-false}
  CENTRALSSH_CAP_SCRIPT_JAIL=${script_jail:-false}
  CENTRALSSH_CAP_PROCSTAT_JAIL=${procstat_jail:-false}
  CENTRALSSH_CAP_VMSTAT_JAIL=${vmstat_jail:-false}

  export CENTRALSSH_CAP_IPFW_HOST CENTRALSSH_CAP_PFCTL_HOST CENTRALSSH_CAP_CARGO_HOST CENTRALSSH_CAP_CARGO_JAIL
  export CENTRALSSH_CAP_VIM_JAIL CENTRALSSH_CAP_VI_JAIL CENTRALSSH_CAP_LESS_JAIL CENTRALSSH_CAP_TOP_JAIL
  export CENTRALSSH_CAP_SCRIPT_JAIL CENTRALSSH_CAP_PROCSTAT_JAIL CENTRALSSH_CAP_VMSTAT_JAIL
}

write_capability_snapshot() {
  cat >"$CENTRALSSH_STAGE_DIR/capabilities.env" <<EOF
script_local=$CENTRALSSH_CAP_SCRIPT
asciinema_local=$CENTRALSSH_CAP_ASCIINEMA
dropbear_local=$CENTRALSSH_CAP_DROPBEAR
putty_local=$CENTRALSSH_CAP_PUTTY
ipfw_host=$CENTRALSSH_CAP_IPFW_HOST
pfctl_host=$CENTRALSSH_CAP_PFCTL_HOST
cargo_host=$CENTRALSSH_CAP_CARGO_HOST
cargo_jail=$CENTRALSSH_CAP_CARGO_JAIL
vim_jail=$CENTRALSSH_CAP_VIM_JAIL
vi_jail=$CENTRALSSH_CAP_VI_JAIL
less_jail=$CENTRALSSH_CAP_LESS_JAIL
top_jail=$CENTRALSSH_CAP_TOP_JAIL
script_jail=$CENTRALSSH_CAP_SCRIPT_JAIL
procstat_jail=$CENTRALSSH_CAP_PROCSTAT_JAIL
vmstat_jail=$CENTRALSSH_CAP_VMSTAT_JAIL
EOF
}
