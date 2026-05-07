stage_forwarding_stress() {
  begin_stage "11-forwarding-stress"
  prepare_askpass_dir "$CENTRALSSH_STAGE_DIR/local-fwd-a" "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1
  with_gateway_askpass ssh -f -N -L 19100:127.0.0.1:22 -L 19101:127.0.0.1:22 -o ExitOnForwardFailure=yes -o "ProxyCommand=$(gateway_proxy_command)" -o PreferredAuthentications=keyboard-interactive -o PubkeyAuthentication=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=yes -p "$CENTRALSSH_GATEWAY_PORT" "qa_proxy@$CENTRALSSH_GATEWAY"
  printf '' | nc 127.0.0.1 19100 >"$CENTRALSSH_STAGE_DIR/fwd-a.banner"
  printf '' | nc 127.0.0.1 19101 >"$CENTRALSSH_STAGE_DIR/fwd-b.banner"
  grep -q '^SSH-' "$CENTRALSSH_STAGE_DIR/fwd-a.banner" || fail_stage_case "forwarding_a" "first forwarded listener missing banner"
  grep -q '^SSH-' "$CENTRALSSH_STAGE_DIR/fwd-b.banner" || fail_stage_case "forwarding_b" "second forwarded listener missing banner"
  pass_stage_case "forwarding_stress" "multiple simultaneous local forwardings worked"
}
