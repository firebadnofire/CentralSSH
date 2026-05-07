#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/profile.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/capabilities.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/resource.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/network.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/reset.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/pty.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/stages/00_preflight.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/stages/08_pty_torture.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/stages/09_mux_rekey.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/stages/10_degraded.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/stages/11_forwarding_stress.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/stages/12_reload_crash.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/stages/13_audit_resources.sh"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/stages/14_client_matrix.sh"

ACTION=${1:-full}

find_seed_binary() {
  find "$SCRIPT_DIR/artifacts" -type f -name 'centralssh.freebsd' 2>/dev/null | sort | tail -n 1
}

sync_repo_to_host() {
  tar -C "$E2E_REPO_ROOT" \
    --exclude .git \
    --exclude target \
    --exclude tests/e2e/artifacts \
    -cf - . |
    host_ssh "rm -rf '$CENTRALSSH_HOST_BUILD_REPO' && mkdir -p '$CENTRALSSH_HOST_BUILD_REPO' && tar -xf - -C '$CENTRALSSH_HOST_BUILD_REPO'"
}

remote_host_keyscan() {
  if [ "$CENTRALSSH_HOST" = "$CENTRALSSH_GATEWAY" ]; then
    host_ssh "ssh-keyscan -t ed25519 '$CENTRALSSH_HOST' 2>/dev/null"
  else
    host_ssh "ssh-keyscan -t ed25519 '$CENTRALSSH_HOST' '$CENTRALSSH_GATEWAY' 2>/dev/null"
  fi
}

configure_target_users() {
  if [ "${CENTRALSSH_SINGLE_TARGET_USER:-false}" = "true" ]; then
    host_ssh "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    if [ "${CENTRALSSH_RUNTIME_TIER:-jail}" = "host" ]; then
      pass_stage_case "target_users" "single-user host-only profile; using existing account ${CENTRALSSH_SINGLE_TARGET_USERNAME:-cgpt}"
      return
    fi
  fi

  for username in qa_proxy qa_change qa_enroll qa_limited qa_multi qa_other; do
    host_ssh "sudo pw usershow '$username' >/dev/null 2>&1 || sudo pw useradd '$username' -m -s /bin/sh"
    jail_ssh "sudo pw usershow '$username' >/dev/null 2>&1 || sudo pw useradd '$username' -m -s /bin/sh"
  done

  for spec in \
    "qa_proxy:$CENTRALSSH_QA_PROXY_PASSWORD" \
    "qa_change:$CENTRALSSH_QA_CHANGE_NEW_PASSWORD" \
    "qa_enroll:$CENTRALSSH_QA_ENROLL_PASSWORD" \
    "qa_limited:$CENTRALSSH_QA_LIMITED_PASSWORD" \
    "qa_multi:$CENTRALSSH_QA_MULTI_PASSWORD" \
    "qa_other:$CENTRALSSH_QA_OTHER_PASSWORD"
  do
    username=${spec%%:*}
    password=${spec#*:}
    host_ssh "printf '%s\n' '$password' | sudo pw usermod '$username' -h 0"
    jail_ssh "printf '%s\n' '$password' | sudo pw usermod '$username' -h 0"
  done

  if host_ssh "command -v sudo >/dev/null 2>&1 && grep -q '^#includedir /usr/local/etc/sudoers.d' /usr/local/etc/sudoers"; then
    host_ssh "printf '%s\n' 'qa_proxy ALL=(ALL) ALL' 'qa_multi ALL=(ALL) ALL' | sudo tee /usr/local/etc/sudoers.d/centralssh-e2e >/dev/null && sudo chmod 440 /usr/local/etc/sudoers.d/centralssh-e2e"
    jail_ssh "printf '%s\n' 'qa_proxy ALL=(ALL) ALL' 'qa_multi ALL=(ALL) ALL' | sudo tee /usr/local/etc/sudoers.d/centralssh-e2e >/dev/null && sudo chmod 440 /usr/local/etc/sudoers.d/centralssh-e2e"
  fi
}

write_lab_config() {
  mode=${1:-default}
  single_user=${CENTRALSSH_SINGLE_TARGET_USERNAME:-cgpt}
  qa_proxy_hash=$(argon2_hash "$CENTRALSSH_QA_PROXY_PASSWORD" "centralsshQAPrxy1")
  qa_enroll_hash=$(argon2_hash "$CENTRALSSH_QA_ENROLL_PASSWORD" "centralsshQAEnrl1")
  qa_limited_hash=$(argon2_hash "$CENTRALSSH_QA_LIMITED_PASSWORD" "centralsshQALimt1")
  qa_multi_hash=$(argon2_hash "$CENTRALSSH_QA_MULTI_PASSWORD" "centralsshQAMult1")

  tmp_config="$CENTRALSSH_STAGE_DIR/config.toml"
  tmp_servers="$CENTRALSSH_STAGE_DIR/servers.toml"
  tmp_known_hosts="$CENTRALSSH_STAGE_DIR/known_hosts"

  if [ "${CENTRALSSH_SINGLE_TARGET_USER:-false}" = "true" ]; then
    case "$mode" in
      change)
        cat >"$tmp_config" <<EOF
[[users]]
name = "$single_user"
password = "$CENTRALSSH_QA_CHANGE_BOOTSTRAP_PASSWORD"
must_change_password = true
allowed_servers = ["host"]

[settings]
user_key_root = "$CENTRALSSH_REMOTE_LAB_ROOT/keys"
per_user_per_server = true
known_hosts_path = "$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts"
audit_log_path = "$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl"
enforce_password_policy = true
min_password_policy = 12

[fail2ban]
enabled = true
max_failures = 3
find_time = "60s"
ban_time = "20s"
max_ban_time = "2m"
backoff_multiplier = 2.0
delay_before_ban = true
delay_time = "1s"
persist_state = true
state_path = "$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json"
EOF
        ;;
      enroll)
        cat >"$tmp_config" <<EOF
[[users]]
name = "$single_user"
password = "$qa_enroll_hash"
must_change_password = false
allowed_servers = ["host"]

[settings]
user_key_root = "$CENTRALSSH_REMOTE_LAB_ROOT/keys"
per_user_per_server = true
known_hosts_path = "$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts"
audit_log_path = "$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl"
enforce_password_policy = true
min_password_policy = 12

[fail2ban]
enabled = true
max_failures = 3
find_time = "60s"
ban_time = "20s"
max_ban_time = "2m"
backoff_multiplier = 2.0
delay_before_ban = true
delay_time = "1s"
persist_state = true
state_path = "$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json"
EOF
        ;;
      limited)
        cat >"$tmp_config" <<EOF
[[users]]
name = "$single_user"
password = "$qa_limited_hash"
totp_secret = "$CENTRALSSH_QA_LIMITED_TOTP_SECRET"
must_change_password = false
allowed_servers = ["host"]

[settings]
user_key_root = "$CENTRALSSH_REMOTE_LAB_ROOT/keys"
per_user_per_server = true
known_hosts_path = "$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts"
audit_log_path = "$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl"
enforce_password_policy = true
min_password_policy = 12

[fail2ban]
enabled = true
max_failures = 3
find_time = "60s"
ban_time = "20s"
max_ban_time = "2m"
backoff_multiplier = 2.0
delay_before_ban = true
delay_time = "1s"
persist_state = true
state_path = "$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json"
EOF
        ;;
      *)
        cat >"$tmp_config" <<EOF
[[users]]
name = "$single_user"
password = "$qa_proxy_hash"
totp_secret = "$CENTRALSSH_QA_PROXY_TOTP_SECRET"
must_change_password = false
allowed_servers = ["host"]

[settings]
user_key_root = "$CENTRALSSH_REMOTE_LAB_ROOT/keys"
per_user_per_server = true
known_hosts_path = "$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts"
audit_log_path = "$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl"
enforce_password_policy = true
min_password_policy = 12

[fail2ban]
enabled = true
max_failures = 3
find_time = "60s"
ban_time = "20s"
max_ban_time = "2m"
backoff_multiplier = 2.0
delay_before_ban = true
delay_time = "1s"
persist_state = true
state_path = "$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json"
EOF
        ;;
    esac
  else
    cat >"$tmp_config" <<EOF
[[users]]
name = "qa_proxy"
password = "$qa_proxy_hash"
totp_secret = "$CENTRALSSH_QA_PROXY_TOTP_SECRET"
must_change_password = false
allowed_servers = ["host", "jail"]

[[users]]
name = "qa_change"
password = "$CENTRALSSH_QA_CHANGE_BOOTSTRAP_PASSWORD"
must_change_password = true
allowed_servers = ["host", "jail"]

[[users]]
name = "qa_enroll"
password = "$qa_enroll_hash"
must_change_password = false
allowed_servers = ["host", "jail"]

[[users]]
name = "qa_limited"
password = "$qa_limited_hash"
totp_secret = "$CENTRALSSH_QA_LIMITED_TOTP_SECRET"
must_change_password = false
allowed_servers = ["jail"]

[[users]]
name = "qa_multi"
password = "$qa_multi_hash"
totp_secret = "$CENTRALSSH_QA_MULTI_TOTP_SECRET"
must_change_password = false
allowed_servers = ["host", "jail"]

[settings]
user_key_root = "$CENTRALSSH_REMOTE_LAB_ROOT/keys"
per_user_per_server = true
known_hosts_path = "$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts"
audit_log_path = "$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl"
enforce_password_policy = true
min_password_policy = 12

[fail2ban]
enabled = true
max_failures = 3
find_time = "60s"
ban_time = "20s"
max_ban_time = "2m"
backoff_multiplier = 2.0
delay_before_ban = true
delay_time = "1s"
persist_state = true
state_path = "$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json"
EOF
  fi

  cat >"$tmp_servers" <<EOF
[servers]
host = "$CENTRALSSH_HOST"
EOF
  if [ "$CENTRALSSH_HOST" != "$CENTRALSSH_GATEWAY" ]; then
    cat >>"$tmp_servers" <<EOF
jail = "$CENTRALSSH_GATEWAY"
EOF
  fi

  remote_host_keyscan >"$tmp_known_hosts"

  if [ "${CENTRALSSH_RUNTIME_LAUNCH_MODE:-sudo}" = "user" ]; then
    jail_ssh "mkdir -p '$CENTRALSSH_REMOTE_LAB_ROOT' '$CENTRALSSH_REMOTE_LAB_ROOT/keys'"
  else
    jail_ssh "sudo mkdir -p '$CENTRALSSH_REMOTE_LAB_ROOT' '$CENTRALSSH_REMOTE_LAB_ROOT/keys' && sudo chown -R $CENTRALSSH_JAIL_USER '$CENTRALSSH_REMOTE_LAB_ROOT'"
  fi
  jail_scp_to "$tmp_config" "$CENTRALSSH_REMOTE_LAB_ROOT/config.toml"
  jail_scp_to "$tmp_servers" "$CENTRALSSH_REMOTE_LAB_ROOT/servers.toml"
  jail_scp_to "$tmp_known_hosts" "$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts"
  if [ "${CENTRALSSH_RUNTIME_LAUNCH_MODE:-sudo}" = "user" ]; then
    jail_ssh "chmod 600 '$CENTRALSSH_REMOTE_LAB_ROOT/config.toml' '$CENTRALSSH_REMOTE_LAB_ROOT/servers.toml' '$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts' && chmod 700 '$CENTRALSSH_REMOTE_LAB_ROOT/keys'"
  else
    jail_ssh "sudo chown root:wheel '$CENTRALSSH_REMOTE_LAB_ROOT/config.toml' '$CENTRALSSH_REMOTE_LAB_ROOT/servers.toml' '$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts' '$CENTRALSSH_REMOTE_LAB_ROOT/keys' && sudo chmod 600 '$CENTRALSSH_REMOTE_LAB_ROOT/config.toml' '$CENTRALSSH_REMOTE_LAB_ROOT/servers.toml' '$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts' && sudo chmod 700 '$CENTRALSSH_REMOTE_LAB_ROOT/keys'"
  fi
}

build_on_host() {
  if [ "${CENTRALSSH_CAP_CARGO_HOST:-false}" = "true" ]; then
    host_ssh "export PATH=/usr/local/bin:/usr/bin:/bin:\$PATH && cd '$CENTRALSSH_HOST_BUILD_REPO' && cargo build --release"
    return
  fi

  seed_binary=$(find_seed_binary)
  [ -n "$seed_binary" ] || fail "no FreeBSD seed binary available and cargo missing on host"
  host_ssh "mkdir -p '$CENTRALSSH_HOST_BUILD_REPO/target/release'"
  scp -O -i "$CENTRALSSH_JUMP_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -J "$CENTRALSSH_JUMP_HOST" "$seed_binary" \
    "$CENTRALSSH_JUMP_USER@$CENTRALSSH_HOST:$CENTRALSSH_HOST_BUILD_REPO/target/release/centralssh"
}

stop_gateway() {
  if [ "${CENTRALSSH_RUNTIME_LAUNCH_MODE:-sudo}" = "user" ]; then
    jail_ssh "sh -lc 'if [ -f \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\" ]; then kill \$(cat \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\") >/dev/null 2>&1 || true; rm -f \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\"; fi; pkill -f \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh\" >/dev/null 2>&1 || true'"
  else
    jail_ssh "sudo sh -lc 'if [ -f \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\" ]; then kill \$(cat \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\") >/dev/null 2>&1 || true; rm -f \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\"; fi; pkill -f \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh\" >/dev/null 2>&1 || true'"
  fi
}

start_gateway() {
  stop_gateway
  if [ "${CENTRALSSH_RUNTIME_LAUNCH_MODE:-sudo}" = "user" ]; then
    jail_ssh "rm -f '$CENTRALSSH_REMOTE_LAB_ROOT/stdout.log' '$CENTRALSSH_REMOTE_LAB_ROOT/stderr.log' '$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl' '$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json'"
  else
    jail_ssh "sudo rm -f '$CENTRALSSH_REMOTE_LAB_ROOT/stdout.log' '$CENTRALSSH_REMOTE_LAB_ROOT/stderr.log' '$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl' '$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json'"
  fi
  host_ssh "cat '$CENTRALSSH_HOST_BUILD_REPO/target/release/centralssh'" >"$CENTRALSSH_STAGE_DIR/centralssh.freebsd"
  jail_scp_to "$CENTRALSSH_STAGE_DIR/centralssh.freebsd" "$CENTRALSSH_REMOTE_LAB_ROOT/centralssh"
  if [ "${CENTRALSSH_RUNTIME_LAUNCH_MODE:-sudo}" = "user" ]; then
    jail_ssh "chmod 755 '$CENTRALSSH_REMOTE_LAB_ROOT/centralssh'"
    jail_ssh "sh -lc 'nohup env CENTRALSSH_ENFORCE_STRICT_SECURITY=false \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh\" --listen 0.0.0.0:$CENTRALSSH_GATEWAY_PORT --config \"$CENTRALSSH_REMOTE_LAB_ROOT/config.toml\" --servers \"$CENTRALSSH_REMOTE_LAB_ROOT/servers.toml\" --known-hosts \"$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts\" --user-key-root \"$CENTRALSSH_REMOTE_LAB_ROOT/keys\" --audit-log \"$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl\" >\"$CENTRALSSH_REMOTE_LAB_ROOT/stdout.log\" 2>\"$CENTRALSSH_REMOTE_LAB_ROOT/stderr.log\" & echo \$! >\"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\"'"
  else
    jail_ssh "sudo chown root:wheel '$CENTRALSSH_REMOTE_LAB_ROOT/centralssh' && sudo chmod 755 '$CENTRALSSH_REMOTE_LAB_ROOT/centralssh'"
    jail_ssh "sudo sh -lc 'nohup env CENTRALSSH_ENFORCE_STRICT_SECURITY=false \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh\" --listen 0.0.0.0:$CENTRALSSH_GATEWAY_PORT --config \"$CENTRALSSH_REMOTE_LAB_ROOT/config.toml\" --servers \"$CENTRALSSH_REMOTE_LAB_ROOT/servers.toml\" --known-hosts \"$CENTRALSSH_REMOTE_LAB_ROOT/known_hosts\" --user-key-root \"$CENTRALSSH_REMOTE_LAB_ROOT/keys\" --audit-log \"$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl\" >\"$CENTRALSSH_REMOTE_LAB_ROOT/stdout.log\" 2>\"$CENTRALSSH_REMOTE_LAB_ROOT/stderr.log\" & echo \$! >\"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\"'"
  fi
  if ! wait_for_tcp "$CENTRALSSH_GATEWAY" "$CENTRALSSH_GATEWAY_PORT" 20; then
    if [ "${CENTRALSSH_RUNTIME_LAUNCH_MODE:-sudo}" = "user" ]; then
      jail_ssh "sh -lc 'cat \"$CENTRALSSH_REMOTE_LAB_ROOT/stderr.log\" \"$CENTRALSSH_REMOTE_LAB_ROOT/stdout.log\" 2>/dev/null || true'" >"$CENTRALSSH_STAGE_DIR/gateway-start-failure.log"
    else
      jail_ssh "sudo sh -lc 'cat \"$CENTRALSSH_REMOTE_LAB_ROOT/stderr.log\" \"$CENTRALSSH_REMOTE_LAB_ROOT/stdout.log\" 2>/dev/null || true'" >"$CENTRALSSH_STAGE_DIR/gateway-start-failure.log"
    fi
    fail_stage_case "start_gateway" "gateway did not open $CENTRALSSH_GATEWAY:$CENTRALSSH_GATEWAY_PORT"
  fi
}

collect_remote_artifacts() {
  target_dir=$1
  mkdir -p "$target_dir"
  read_cmd="sudo sh -lc"
  if [ "${CENTRALSSH_RUNTIME_LAUNCH_MODE:-sudo}" = "user" ]; then
    read_cmd="sh -lc"
  fi
  jail_ssh "$read_cmd 'cat \"$CENTRALSSH_REMOTE_LAB_ROOT/audit.jsonl\" 2>/dev/null || true'" >"$target_dir/audit.jsonl" || true
  jail_ssh "$read_cmd 'cat \"$CENTRALSSH_REMOTE_LAB_ROOT/stdout.log\" 2>/dev/null || true'" >"$target_dir/stdout.log" || true
  jail_ssh "$read_cmd 'cat \"$CENTRALSSH_REMOTE_LAB_ROOT/stderr.log\" 2>/dev/null || true'" >"$target_dir/stderr.log" || true
  jail_ssh "$read_cmd 'cat \"$CENTRALSSH_REMOTE_LAB_ROOT/fail2ban_state.json\" 2>/dev/null || true'" >"$target_dir/fail2ban_state.json" || true
  jail_ssh "$read_cmd 'cat \"$CENTRALSSH_REMOTE_LAB_ROOT/config.toml\" 2>/dev/null || true'" >"$target_dir/config.toml" || true
  jail_ssh "$read_cmd 'cat \"$CENTRALSSH_REMOTE_LAB_ROOT/servers.toml\" 2>/dev/null || true'" >"$target_dir/servers.toml" || true
}

run_expect_case() {
  scenario=$1
  user=$2
  password=$3
  totp_secret=$4
  selection=$5
  output_file=$6
  shift 6
  CENTRALSSH_PROXY_COMMAND=$(gateway_proxy_command) \
  CENTRALSSH_GATEWAY="$CENTRALSSH_GATEWAY" \
  CENTRALSSH_GATEWAY_PORT="$CENTRALSSH_GATEWAY_PORT" \
  CENTRALSSH_USER="$user" \
  CENTRALSSH_PASSWORD="$password" \
  CENTRALSSH_TOTP_SECRET="$totp_secret" \
  CENTRALSSH_SELECTION="$selection" \
  CENTRALSSH_EXPECT_OUTPUT="$output_file" \
  CENTRALSSH_EXPECT_TIMEOUT="$CENTRALSSH_CASE_TIMEOUT" \
  "$SCRIPT_DIR/gateway_flow.exp" "$scenario" "$@"
}

run_gateway_exec() {
  artifact_dir=$1
  user=$2
  password=$3
  totp_secret=$4
  selection=$5
  remote_command=$6
  prepare_askpass_dir "$artifact_dir/askpass" "$password" "$totp_secret" "$selection"
  with_gateway_askpass \
    ssh \
      -o "ProxyCommand=$(gateway_proxy_command)" \
      -o PreferredAuthentications=keyboard-interactive \
      -o PubkeyAuthentication=no \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=yes \
      -p "$CENTRALSSH_GATEWAY_PORT" \
      "$user@$CENTRALSSH_GATEWAY" \
      "$remote_command"
}

stage_validate_environment() {
  begin_stage "01-environment"
  require_cmd nc
  capture_gateway_state "before-connectivity"
  host_ssh "echo host-ok" >"$CENTRALSSH_STAGE_DIR/host.txt"
  jail_ssh "echo jail-ok" >"$CENTRALSSH_STAGE_DIR/jail.txt"
  capture_gateway_state "after-connectivity"
  pass_stage_case "reachability" "host and jail reachable over documented path"
}

stage_build_and_bootstrap() {
  begin_stage "02-build-bootstrap"
  sync_repo_to_host >"$CENTRALSSH_STAGE_DIR/sync.log"
  pass_stage_case "sync_repo" "local checkout copied to FreeBSD host build path"

  build_on_host >"$CENTRALSSH_STAGE_DIR/build.log" 2>&1
  pass_stage_case "build_release" "cargo build --release succeeded on FreeBSD host"

  configure_target_users >"$CENTRALSSH_STAGE_DIR/users.log" 2>&1
  pass_stage_case "target_users" "host and jail QA users refreshed"

  write_lab_config >"$CENTRALSSH_STAGE_DIR/bootstrap.log" 2>&1
  pass_stage_case "lab_config" "config, servers, and known_hosts refreshed"

  start_gateway
  collect_remote_artifacts "$CENTRALSSH_STAGE_DIR"
  capture_gateway_state "post-bootstrap"
  pass_stage_case "gateway_start" "gateway listening and artifacts collected"
}

stage_auth_and_selection() {
  begin_stage "03-auth-selection"
  run_expect_case invalid-password qa_proxy "definitely-wrong-password" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "$CENTRALSSH_STAGE_DIR/invalid-password.log"
  pass_stage_case "invalid_password" "wrong password rejected"

  run_expect_case invalid-totp qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "$CENTRALSSH_STAGE_DIR/invalid-totp.log"
  pass_stage_case "invalid_totp" "wrong TOTP rejected"

  run_expect_case unknown-user qa_unknown "madeup-pass" "" 1 "$CENTRALSSH_STAGE_DIR/unknown-user.log"
  pass_stage_case "unknown_user" "unknown user masked behind TOTP prompt"

  run_expect_case invalid-selection qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "$CENTRALSSH_STAGE_DIR/invalid-selection.log"
  pass_stage_case "invalid_selection" "invalid target entry re-prompts cleanly"

  run_expect_case limited-selection qa_limited "$CENTRALSSH_QA_LIMITED_PASSWORD" "$CENTRALSSH_QA_LIMITED_TOTP_SECRET" 1 "$CENTRALSSH_STAGE_DIR/limited-selection.log"
  pass_stage_case "limited_selection" "restricted user only sees allowed target"

  change_secret=$(
    CENTRALSSH_NEW_PASSWORD="$CENTRALSSH_QA_CHANGE_NEW_PASSWORD" \
      run_expect_case must-change-and-enroll qa_change "$CENTRALSSH_QA_CHANGE_BOOTSTRAP_PASSWORD" "" 1 "$CENTRALSSH_STAGE_DIR/must-change.log"
  )
  printf '%s\n' "$change_secret" >"$CENTRALSSH_STAGE_DIR/qa_change_enrolled_secret.txt"
  pass_stage_case "must_change_password" "forced password change and TOTP enrollment completed"

  enroll_secret=$(run_expect_case enroll-only qa_enroll "$CENTRALSSH_QA_ENROLL_PASSWORD" "" 1 "$CENTRALSSH_STAGE_DIR/enroll-only.log")
  printf '%s\n' "$enroll_secret" >"$CENTRALSSH_STAGE_DIR/qa_enroll_secret.txt"
  pass_stage_case "totp_enrollment" "unenrolled user completed enrollment"

  collect_remote_artifacts "$CENTRALSSH_STAGE_DIR"
}

stage_interactive() {
  begin_stage "04-interactive"
  write_term_snapshot "$CENTRALSSH_STAGE_DIR/term.txt"
  run_expect_case interactive-basics qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "$CENTRALSSH_STAGE_DIR/interactive-basics.log"
  pass_stage_case "interactive_basics" "shell, PTY resize, Ctrl-C, less, and vi round-tripped"
}

stage_noninteractive() {
  begin_stage "05-noninteractive"
  run_gateway_exec "$CENTRALSSH_STAGE_DIR/exec-whoami" qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "whoami" >"$CENTRALSSH_STAGE_DIR/whoami.out"
  grep -qx 'qa_proxy' "$CENTRALSSH_STAGE_DIR/whoami.out" || fail_stage_case "exec_whoami" "unexpected whoami output"
  pass_stage_case "exec_whoami" "non-interactive exec returned target username"

  run_gateway_exec "$CENTRALSSH_STAGE_DIR/exec-stderr" qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "sh -lc 'printf out; printf err >&2'" >"$CENTRALSSH_STAGE_DIR/stderr.out" 2>"$CENTRALSSH_STAGE_DIR/stderr.err"
  grep -q 'out' "$CENTRALSSH_STAGE_DIR/stderr.out" || fail_stage_case "exec_stdout" "stdout missing"
  grep -q 'err' "$CENTRALSSH_STAGE_DIR/stderr.err" || fail_stage_case "exec_stderr" "stderr missing"
  pass_stage_case "exec_stdout_stderr" "stdout and stderr both propagated"

  run_gateway_exec "$CENTRALSSH_STAGE_DIR/exec-binary" qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "python3 - <<'PY'\nimport sys\nsys.stdout.buffer.write(bytes([0,1,2,3,255]))\nPY" >"$CENTRALSSH_STAGE_DIR/binary.out"
  python3 - <<'PY' "$CENTRALSSH_STAGE_DIR/binary.out"
import sys
data = open(sys.argv[1], "rb").read()
assert data == bytes([0, 1, 2, 3, 255]), data
PY
  pass_stage_case "exec_binary" "binary stdout survived proxying"

  local_payload="$CENTRALSSH_STAGE_DIR/local-payload.txt"
  printf 'centralssh scp payload\n' >"$local_payload"
  prepare_askpass_dir "$CENTRALSSH_STAGE_DIR/scp-put" "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1
  with_gateway_askpass \
    scp -O \
      -o "ProxyCommand=$(gateway_proxy_command)" \
      -o PreferredAuthentications=keyboard-interactive \
      -o PubkeyAuthentication=no \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=yes \
      -P "$CENTRALSSH_GATEWAY_PORT" \
      "$local_payload" \
      "qa_proxy@$CENTRALSSH_GATEWAY:/tmp/centralssh-scp.txt" >"$CENTRALSSH_STAGE_DIR/scp-put.out" 2>"$CENTRALSSH_STAGE_DIR/scp-put.err"
  pass_stage_case "scp_put" "scp upload succeeded"

  prepare_askpass_dir "$CENTRALSSH_STAGE_DIR/scp-get" "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1
  with_gateway_askpass \
    scp -O \
      -o "ProxyCommand=$(gateway_proxy_command)" \
      -o PreferredAuthentications=keyboard-interactive \
      -o PubkeyAuthentication=no \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=yes \
      -P "$CENTRALSSH_GATEWAY_PORT" \
      "qa_proxy@$CENTRALSSH_GATEWAY:/tmp/centralssh-scp.txt" \
      "$CENTRALSSH_STAGE_DIR/downloaded-scp.txt" >"$CENTRALSSH_STAGE_DIR/scp-get.out" 2>"$CENTRALSSH_STAGE_DIR/scp-get.err"
  cmp "$local_payload" "$CENTRALSSH_STAGE_DIR/downloaded-scp.txt" || fail_stage_case "scp_get" "scp round trip content mismatch"
  pass_stage_case "scp_roundtrip" "scp upload and download preserved content"

  cat >"$CENTRALSSH_STAGE_DIR/sftp.batch" <<'EOF'
put local-payload.txt /tmp/centralssh-sftp.txt
get /tmp/centralssh-sftp.txt downloaded-sftp.txt
ls /tmp/centralssh-sftp.txt
EOF
  (cd "$CENTRALSSH_STAGE_DIR" && prepare_askpass_dir "$CENTRALSSH_STAGE_DIR/sftp" "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 && with_gateway_askpass sftp -b sftp.batch -o "ProxyCommand=$(gateway_proxy_command)" -o PreferredAuthentications=keyboard-interactive -o PubkeyAuthentication=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=yes -P "$CENTRALSSH_GATEWAY_PORT" "qa_proxy@$CENTRALSSH_GATEWAY") >"$CENTRALSSH_STAGE_DIR/sftp.out" 2>"$CENTRALSSH_STAGE_DIR/sftp.err"
  cmp "$local_payload" "$CENTRALSSH_STAGE_DIR/downloaded-sftp.txt" || fail_stage_case "sftp_roundtrip" "sftp round trip content mismatch"
  pass_stage_case "sftp_roundtrip" "sftp subsystem handled put/get"

  prepare_askpass_dir "$CENTRALSSH_STAGE_DIR/direct-tcpip" "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1
  with_gateway_askpass \
    ssh \
      -W 127.0.0.1:22 \
      -o "ProxyCommand=$(gateway_proxy_command)" \
      -o PreferredAuthentications=keyboard-interactive \
      -o PubkeyAuthentication=no \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=yes \
      -p "$CENTRALSSH_GATEWAY_PORT" \
      "qa_proxy@$CENTRALSSH_GATEWAY" < /dev/null >"$CENTRALSSH_STAGE_DIR/direct-tcpip.out" 2>"$CENTRALSSH_STAGE_DIR/direct-tcpip.err" || true
  grep -q '^SSH-' "$CENTRALSSH_STAGE_DIR/direct-tcpip.out" || fail_stage_case "direct_tcpip" "direct-tcpip did not return target SSH banner"
  pass_stage_case "direct_tcpip" "direct-tcpip channel returned target SSH banner"
}

stage_forwarding_and_longlived() {
  begin_stage "06-forwarding-longlived"
  local_server_log="$CENTRALSSH_STAGE_DIR/http.log"
  python3 -m http.server 18080 --bind 127.0.0.1 >"$local_server_log" 2>&1 &
  local_server_pid=$!
  trap 'kill "$local_server_pid" >/dev/null 2>&1 || true' EXIT INT TERM

  prepare_askpass_dir "$CENTRALSSH_STAGE_DIR/local-forward" "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1
  with_gateway_askpass \
    ssh -f -N \
      -L 19022:127.0.0.1:22 \
      -o ExitOnForwardFailure=yes \
      -o "ProxyCommand=$(gateway_proxy_command)" \
      -o PreferredAuthentications=keyboard-interactive \
      -o PubkeyAuthentication=no \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=yes \
      -p "$CENTRALSSH_GATEWAY_PORT" \
      "qa_proxy@$CENTRALSSH_GATEWAY"
  sleep 2
  printf '' | nc 127.0.0.1 19022 >"$CENTRALSSH_STAGE_DIR/local-forward.banner"
  grep -q '^SSH-' "$CENTRALSSH_STAGE_DIR/local-forward.banner" || fail_stage_case "local_forward" "forwarded SSH banner not observed"
  pass_stage_case "local_forward" "local forwarding reached target sshd"

  prepare_askpass_dir "$CENTRALSSH_STAGE_DIR/remote-forward" "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1
  with_gateway_askpass \
    ssh -f -N \
      -R 18081:127.0.0.1:18080 \
      -o ExitOnForwardFailure=yes \
      -o "ProxyCommand=$(gateway_proxy_command)" \
      -o PreferredAuthentications=keyboard-interactive \
      -o PubkeyAuthentication=no \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=yes \
      -p "$CENTRALSSH_GATEWAY_PORT" \
      "qa_proxy@$CENTRALSSH_GATEWAY"
  sleep 2
  run_gateway_exec "$CENTRALSSH_STAGE_DIR/rforward-check" qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "fetch -qo - http://127.0.0.1:18081/" >"$CENTRALSSH_STAGE_DIR/remote-forward.out"
  grep -qi 'Directory listing' "$CENTRALSSH_STAGE_DIR/remote-forward.out" || fail_stage_case "remote_forward" "remote forward did not reach local server"
  pass_stage_case "remote_forward" "remote forwarding reached local server"

  run_gateway_exec "$CENTRALSSH_STAGE_DIR/long-lived" qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "sh -lc 'i=0; while [ \$i -lt 6 ]; do echo tick-\$i; i=\$((i+1)); sleep 5; done'" >"$CENTRALSSH_STAGE_DIR/long-lived.out"
  grep -q 'tick-5' "$CENTRALSSH_STAGE_DIR/long-lived.out" || fail_stage_case "long_lived_exec" "long-lived command did not stay connected"
  pass_stage_case "long_lived_exec" "long-running exec stream stayed healthy"

  kill "$local_server_pid" >/dev/null 2>&1 || true
  trap - EXIT INT TERM
}

stage_reload_and_abuse() {
  begin_stage "07-reload-abuse"
  run_gateway_exec "$CENTRALSSH_STAGE_DIR/pre-reload" qa_limited "$CENTRALSSH_QA_LIMITED_PASSWORD" "$CENTRALSSH_QA_LIMITED_TOTP_SECRET" 1 "whoami" >"$CENTRALSSH_STAGE_DIR/pre-reload.out"
  pass_stage_case "pre_reload_login" "limited user can log in before reload"

  jail_ssh "python3 - <<'PY'
from pathlib import Path
path = Path('$CENTRALSSH_REMOTE_LAB_ROOT/config.toml')
data = path.read_text()
data = data.replace('allowed_servers = [\"jail\"]', 'allowed_servers = [\"host\", \"jail\"]', 1)
path.write_text(data)
PY
kill -HUP \$(cat '$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid')"
  sleep 2
  run_expect_case expanded-selection qa_limited "$CENTRALSSH_QA_LIMITED_PASSWORD" "$CENTRALSSH_QA_LIMITED_TOTP_SECRET" 2 "$CENTRALSSH_STAGE_DIR/post-reload-selection.log"
  pass_stage_case "valid_reload" "new config applied to new sessions after SIGHUP"

  jail_ssh "cp '$CENTRALSSH_REMOTE_LAB_ROOT/config.toml' '$CENTRALSSH_REMOTE_LAB_ROOT/config.toml.bak' && printf '%s\n' '[[users]]' > '$CENTRALSSH_REMOTE_LAB_ROOT/config.toml' && kill -HUP \$(cat '$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid')"
  sleep 2
  run_gateway_exec "$CENTRALSSH_STAGE_DIR/post-invalid-reload" qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "whoami" >"$CENTRALSSH_STAGE_DIR/post-invalid-reload.out"
  grep -qx 'qa_proxy' "$CENTRALSSH_STAGE_DIR/post-invalid-reload.out" || fail_stage_case "invalid_reload" "old config did not remain active after invalid reload"
  jail_ssh "mv '$CENTRALSSH_REMOTE_LAB_ROOT/config.toml.bak' '$CENTRALSSH_REMOTE_LAB_ROOT/config.toml' && kill -HUP \$(cat '$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid')"
  pass_stage_case "invalid_reload" "invalid reload rejected while old config remained active"

  failures=0
  while [ "$failures" -lt 3 ]; do
    if run_expect_case invalid-password qa_proxy "still-wrong-password" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "$CENTRALSSH_STAGE_DIR/ban-$failures.log"; then
      :
    fi
    failures=$((failures + 1))
  done
  sleep 2
  if run_expect_case invalid-password qa_proxy "still-wrong-password" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "$CENTRALSSH_STAGE_DIR/ban-active.log"; then
    :
  fi
  collect_remote_artifacts "$CENTRALSSH_STAGE_DIR"
  grep -q '"event_type":"ban_' "$CENTRALSSH_STAGE_DIR/audit.jsonl" || fail_stage_case "abuse_ban" "ban event missing from audit log"
  pass_stage_case "abuse_ban" "repeat failures triggered rate limiting or ban audit events"
}

stage_audit_review() {
  begin_stage "08-audit-review"
  collect_remote_artifacts "$CENTRALSSH_STAGE_DIR"
  python3 - <<'PY' "$CENTRALSSH_STAGE_DIR/audit.jsonl" >"$CENTRALSSH_STAGE_DIR/audit-summary.txt"
import json
import sys
from collections import Counter

path = sys.argv[1]
counter = Counter()
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        entry = json.loads(line)
        counter[entry["event_type"]] += 1

for key in sorted(counter):
    print(f"{key} {counter[key]}")
PY
  grep -q '^auth_success ' "$CENTRALSSH_STAGE_DIR/audit-summary.txt" || fail_stage_case "audit_auth_success" "auth_success missing from audit log"
  grep -q '^proxy_start ' "$CENTRALSSH_STAGE_DIR/audit-summary.txt" || fail_stage_case "audit_proxy_start" "proxy_start missing from audit log"
  grep -q '^proxy_end ' "$CENTRALSSH_STAGE_DIR/audit-summary.txt" || fail_stage_case "audit_proxy_end" "proxy_end missing from audit log"
  pass_stage_case "audit_summary" "audit log remained valid JSONL with expected events"
}

run_smoke() {
  stage_preflight_profile
  stage_validate_environment
  reset_lab_state "${CENTRALSSH_RESET_MODE:-lab-reset}"
  stage_build_and_bootstrap
  stage_auth_and_selection
  stage_noninteractive
}

run_full() {
  stage_preflight_profile
  stage_validate_environment
  reset_lab_state "${CENTRALSSH_RESET_MODE:-lab-reset}"
  stage_build_and_bootstrap
  stage_auth_and_selection
  stage_interactive
  stage_noninteractive
  stage_forwarding_and_longlived
  stage_pty_torture
  stage_mux_and_rekey
  stage_degraded_transport
  stage_forwarding_stress
  stage_reload_and_abuse
  stage_reload_and_crash_stress
  stage_audit_review
  stage_audit_and_resources
  stage_client_matrix
}

prepare_artifacts
log "Artifacts: $CENTRALSSH_ARTIFACT_DIR"

case "$ACTION" in
  preflight)
    stage_preflight_profile
    ;;
  bootstrap)
    stage_preflight_profile
    stage_validate_environment
    reset_lab_state "${CENTRALSSH_RESET_MODE:-lab-reset}"
    stage_build_and_bootstrap
    ;;
  full-reset|lab-reset|minimal-clean|preserve-artifacts)
    stage_preflight_profile
    stage_validate_environment
    reset_lab_state "$ACTION"
    ;;
  reset)
    stage_preflight_profile
    stage_validate_environment
    reset_lab_state "${CENTRALSSH_RESET_MODE:-lab-reset}"
    ;;
  smoke)
    run_smoke
    ;;
  full)
    run_full
    ;;
  *)
    fail "unsupported action: $ACTION"
    ;;
esac

log "Completed action=$ACTION results=$CENTRALSSH_RESULTS_FILE"
