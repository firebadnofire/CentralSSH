stage_preflight_profile() {
  begin_stage "00-profile"
  profile_load
  profile_validate_contract
  profile_write_snapshot "$CENTRALSSH_STAGE_DIR/profile.env"
  detect_local_capabilities
  detect_remote_capabilities
  write_capability_snapshot
  capture_gateway_state "preflight"
  pass_stage_case "profile_loaded" "profile and capabilities recorded"
}
