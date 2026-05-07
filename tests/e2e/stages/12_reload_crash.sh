stage_reload_and_crash_stress() {
  begin_stage "12-reload-crash"
  capture_gateway_state "before-reload-stress"
  i=0
  while [ "$i" -lt 3 ]; do
    jail_ssh "sudo kill -HUP \$(cat '$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid')"
    sleep 1
    i=$((i + 1))
  done
  run_gateway_exec "$CENTRALSSH_STAGE_DIR/reload-stress" qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "whoami" >"$CENTRALSSH_STAGE_DIR/reload-stress.out"
  grep -qx 'qa_proxy' "$CENTRALSSH_STAGE_DIR/reload-stress.out" || fail_stage_case "reload_stress" "session creation failed after repeated reloads"

  jail_ssh "sudo kill -STOP \$(cat '$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid')"
  sleep 2
  jail_ssh "sudo kill -CONT \$(cat '$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid')"
  run_gateway_exec "$CENTRALSSH_STAGE_DIR/post-stop-cont" qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "whoami" >"$CENTRALSSH_STAGE_DIR/post-stop-cont.out"
  grep -qx 'qa_proxy' "$CENTRALSSH_STAGE_DIR/post-stop-cont.out" || fail_stage_case "stop_cont" "gateway did not recover after SIGSTOP/SIGCONT"

  stop_gateway
  start_gateway
  capture_gateway_state "after-crash-restart"
  pass_stage_case "reload_crash" "reload stress and stop/cont restart path exercised"
}
