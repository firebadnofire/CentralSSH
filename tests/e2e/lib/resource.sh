#!/bin/sh
set -eu

capture_local_resource_snapshot() {
  label=$1
  out="$CENTRALSSH_STAGE_DIR/resources-local-$label.txt"
  {
    echo "# local $(timestamp_utc)"
    echo "cwd=$E2E_REPO_ROOT"
    echo "pid=$$"
    ulimit -a 2>/dev/null || true
    netstat -an 2>/dev/null | head -n 200 || true
  } >"$out"
}

capture_remote_resource_snapshot() {
  label=$1
  out="$CENTRALSSH_STAGE_DIR/resources-remote-$label.txt"
  jail_ssh "sudo sh -lc '
echo \"# remote $(date -u +%Y-%m-%dT%H:%M:%SZ)\"
sockstat -4 -6 || true
netstat -an || true
ps -axo pid,ppid,user,state,nlwp,rss,etimes,command || true
if [ -f \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\" ]; then
  pid=\$(cat \"$CENTRALSSH_REMOTE_LAB_ROOT/centralssh.pid\")
  echo \"gateway_pid=\$pid\"
  procstat -f \$pid 2>/dev/null || true
  procstat -t \$pid 2>/dev/null || true
fi
'" >"$out"
}

capture_gateway_state() {
  label=$1
  capture_local_resource_snapshot "$label"
  capture_remote_resource_snapshot "$label"
}
