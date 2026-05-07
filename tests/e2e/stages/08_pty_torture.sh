stage_pty_torture() {
  begin_stage "08-pty-torture"
  write_term_snapshot "$CENTRALSSH_STAGE_DIR/term.txt"
  if [ "${CENTRALSSH_CAP_VI_JAIL:-false}" != "true" ] && [ "${CENTRALSSH_CAP_VIM_JAIL:-false}" != "true" ]; then
    skip_stage_case "pty_torture" "vi or vim not present on target"
    return
  fi
  pty_record_wrapper "$CENTRALSSH_STAGE_DIR/pty-torture" \
    env TERM=xterm-256color \
    CENTRALSSH_PROXY_COMMAND="$(gateway_proxy_command)" \
    CENTRALSSH_GATEWAY="$CENTRALSSH_GATEWAY" \
    CENTRALSSH_GATEWAY_PORT="$CENTRALSSH_GATEWAY_PORT" \
    CENTRALSSH_USER="qa_proxy" \
    CENTRALSSH_PASSWORD="$CENTRALSSH_QA_PROXY_PASSWORD" \
    CENTRALSSH_TOTP_SECRET="$CENTRALSSH_QA_PROXY_TOTP_SECRET" \
    CENTRALSSH_SELECTION="1" \
    CENTRALSSH_EXPECT_OUTPUT="$CENTRALSSH_STAGE_DIR/pty-torture.expect.log" \
    CENTRALSSH_EXPECT_TIMEOUT="$CENTRALSSH_CASE_TIMEOUT" \
    "$E2E_LIB_DIR/expect/gateway_flow.exp" interactive-basics
  pass_stage_case "pty_torture" "PTY session captured with term snapshot and transcript"
}
