stage_mux_and_rekey() {
  begin_stage "09-mux-rekey"
  mux_dir="$CENTRALSSH_STAGE_DIR/mux"
  mkdir -p "$mux_dir"
  prepare_askpass_dir "$mux_dir/askpass" "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1
  control_path="$mux_dir/control.sock"
  common_opts="-o ProxyCommand=$(gateway_proxy_command) -o PreferredAuthentications=keyboard-interactive -o PubkeyAuthentication=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=yes -o ControlMaster=yes -o ControlPersist=30 -o ControlPath=$control_path -o RekeyLimit=16K -p $CENTRALSSH_GATEWAY_PORT"

  with_gateway_askpass ssh $common_opts -f -N "qa_proxy@$CENTRALSSH_GATEWAY"
  with_gateway_askpass ssh -S "$control_path" -O check "qa_proxy@$CENTRALSSH_GATEWAY" >"$CENTRALSSH_STAGE_DIR/mux-check.out" 2>&1 || fail_stage_case "mux_master" "control master did not stay up"
  with_gateway_askpass ssh -S "$control_path" -o ControlMaster=no -p "$CENTRALSSH_GATEWAY_PORT" -o "ProxyCommand=$(gateway_proxy_command)" "qa_proxy@$CENTRALSSH_GATEWAY" "whoami" >"$CENTRALSSH_STAGE_DIR/mux-exec.out"
  grep -qx 'qa_proxy' "$CENTRALSSH_STAGE_DIR/mux-exec.out" || fail_stage_case "mux_exec" "mux exec output mismatch"
  with_gateway_askpass ssh -S "$control_path" -o ControlMaster=no -L 19023:127.0.0.1:22 -f -N -p "$CENTRALSSH_GATEWAY_PORT" -o "ProxyCommand=$(gateway_proxy_command)" "qa_proxy@$CENTRALSSH_GATEWAY"
  printf '' | nc 127.0.0.1 19023 >"$CENTRALSSH_STAGE_DIR/mux-forward.banner"
  grep -q '^SSH-' "$CENTRALSSH_STAGE_DIR/mux-forward.banner" || fail_stage_case "mux_forward" "multiplexed forward did not produce banner"
  with_gateway_askpass ssh -S "$control_path" -O exit "qa_proxy@$CENTRALSSH_GATEWAY" >"$CENTRALSSH_STAGE_DIR/mux-exit.out" 2>&1 || true
  pass_stage_case "mux_rekey" "ControlMaster, exec, forwarding, and low RekeyLimit exercised"
}
