#!/bin/sh
set -eu

profile_load() {
  if [ -n "${CENTRALSSH_PROFILE_FILE:-}" ]; then
    # shellcheck disable=SC1090
    . "$CENTRALSSH_PROFILE_FILE"
    return
  fi

  if [ -n "${CENTRALSSH_E2E_ENV_FILE:-}" ]; then
    # shellcheck disable=SC1090
    . "$CENTRALSSH_E2E_ENV_FILE"
    return
  fi

  if [ -n "${CENTRALSSH_PROFILE:-}" ]; then
    profile_path="$E2E_LIB_DIR/profiles/$CENTRALSSH_PROFILE.env"
    [ -f "$profile_path" ] || fail "missing profile file: $profile_path"
    # shellcheck disable=SC1090
    . "$profile_path"
    return
  fi

  default_profile="$E2E_LIB_DIR/profiles/freebsd-host-jail-141-151.env"
  [ -f "$default_profile" ] || fail "missing default profile file: $default_profile"
  # shellcheck disable=SC1090
  . "$default_profile"
}

profile_write_snapshot() {
  snapshot_path=$1
  cat >"$snapshot_path" <<EOF
profile_id=${CENTRALSSH_PROFILE_ID:-unknown}
description=${CENTRALSSH_PROFILE_DESCRIPTION:-}
jump_host=${CENTRALSSH_JUMP_HOST:-}
host=${CENTRALSSH_HOST:-}
gateway=${CENTRALSSH_GATEWAY:-}
gateway_port=${CENTRALSSH_GATEWAY_PORT:-}
build_tier=${CENTRALSSH_BUILD_TIER:-}
runtime_tier=${CENTRALSSH_RUNTIME_TIER:-}
impairment_tier=${CENTRALSSH_IMPAIRMENT_TIER:-}
runtime_launch_mode=${CENTRALSSH_RUNTIME_LAUNCH_MODE:-}
client_matrix=${CENTRALSSH_CLIENT_MATRIX:-}
cwd=$E2E_REPO_ROOT
EOF
}

profile_validate_contract() {
  require_env CENTRALSSH_JUMP_HOST
  require_env CENTRALSSH_HOST
  require_env CENTRALSSH_GATEWAY
  require_env CENTRALSSH_GATEWAY_PORT
  require_env CENTRALSSH_JUMP_USER
  require_env CENTRALSSH_JUMP_KEY
  require_env CENTRALSSH_REMOTE_LAB_ROOT
  require_env CENTRALSSH_HOST_BUILD_REPO
  require_env CENTRALSSH_RUNTIME_LAUNCH_MODE
  : "${CENTRALSSH_RUNTIME_TIER:=jail}"
}
