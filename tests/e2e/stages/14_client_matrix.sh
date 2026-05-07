stage_client_matrix() {
  begin_stage "14-client-matrix"
  pass_stage_case "openssh_current" "OpenSSH current path covered by the main suite"
  if [ "${CENTRALSSH_CAP_DROPBEAR:-false}" = "true" ]; then
    skip_stage_case "dropbear" "Dropbear client detection present; dedicated workflow not yet wired"
  else
    skip_stage_case "dropbear" "dbclient not installed locally"
  fi
  if [ "${CENTRALSSH_CAP_PUTTY:-false}" = "true" ]; then
    skip_stage_case "putty" "Plink detected; dedicated workflow not yet wired"
  else
    skip_stage_case "putty" "Plink not installed locally"
  fi
}
