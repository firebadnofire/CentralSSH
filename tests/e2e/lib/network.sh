#!/bin/sh
set -eu

impairment_clear() {
  if [ "${CENTRALSSH_CAP_IPFW_HOST:-false}" = "true" ]; then
    host_ssh "sudo ipfw -q delete 42000 42001 42002 >/dev/null 2>&1 || true; sudo ipfw -q pipe delete 42000 >/dev/null 2>&1 || true"
  fi
}

impairment_apply_ipfw() {
  delay_ms=$1
  plr=$2
  bw=$3
  host_ssh "sudo ipfw -q pipe 42000 config delay ${delay_ms}ms plr $plr bw $bw && \
sudo ipfw -q add 42000 pipe 42000 tcp from any to $CENTRALSSH_GATEWAY $CENTRALSSH_GATEWAY_PORT && \
sudo ipfw -q add 42001 pipe 42000 tcp from $CENTRALSSH_GATEWAY $CENTRALSSH_GATEWAY_PORT to any"
}

impairment_record_state() {
  out="$CENTRALSSH_STAGE_DIR/network-impairment.txt"
  if [ "${CENTRALSSH_CAP_IPFW_HOST:-false}" = "true" ]; then
    host_ssh "sudo ipfw -a list 2>/dev/null || true; sudo ipfw pipe show 2>/dev/null || true" >"$out"
  else
    printf 'no impairment capability detected\n' >"$out"
  fi
}
