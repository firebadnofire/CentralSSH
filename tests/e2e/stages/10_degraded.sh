stage_degraded_transport() {
  begin_stage "10-degraded"
  if [ "${CENTRALSSH_CAP_IPFW_HOST:-false}" != "true" ]; then
    impairment_record_state
    skip_stage_case "degraded_transport" "no host-side ipfw/dummynet capability detected"
    return
  fi

  impairment_clear
  impairment_apply_ipfw 120 0.05 2Mbit/s
  impairment_record_state
  run_gateway_exec "$CENTRALSSH_STAGE_DIR/degraded-exec" qa_proxy "$CENTRALSSH_QA_PROXY_PASSWORD" "$CENTRALSSH_QA_PROXY_TOTP_SECRET" 1 "sh -lc 'i=0; while [ \$i -lt 8 ]; do echo degraded-\$i; i=\$((i+1)); sleep 1; done'" >"$CENTRALSSH_STAGE_DIR/degraded.out"
  grep -q 'degraded-7' "$CENTRALSSH_STAGE_DIR/degraded.out" || fail_stage_case "degraded_exec" "degraded transport stream stalled or truncated"
  impairment_clear
  pass_stage_case "degraded_transport" "latency/loss/bandwidth impairment applied and recovered"
}
