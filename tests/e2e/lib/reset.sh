#!/bin/sh
set -eu

reset_lab_state() {
  mode=$1
  case "$mode" in
    full-reset)
      jail_ssh "sudo rm -rf '$CENTRALSSH_REMOTE_LAB_ROOT' && sudo mkdir -p '$CENTRALSSH_REMOTE_LAB_ROOT'"
      ;;
    lab-reset)
      jail_ssh "sudo rm -rf '$CENTRALSSH_REMOTE_LAB_ROOT/keys' '$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl' '$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json' '$CENTRALSSH_REMOTE_LAB_ROOT/stdout.log' '$CENTRALSSH_REMOTE_LAB_ROOT/stderr.log' && sudo mkdir -p '$CENTRALSSH_REMOTE_LAB_ROOT'"
      ;;
    minimal-clean)
      stop_gateway >/dev/null 2>&1 || true
      jail_ssh "sudo rm -f '$CENTRALSSH_REMOTE_LAB_ROOT/stdout.log' '$CENTRALSSH_REMOTE_LAB_ROOT/stderr.log' '$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl' '$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json'"
      ;;
    preserve-artifacts)
      :
      ;;
    *)
      fail "unsupported reset mode: $mode"
      ;;
  esac
}
