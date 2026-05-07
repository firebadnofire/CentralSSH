stage_audit_and_resources() {
  begin_stage "13-audit-resources"
  collect_remote_artifacts "$CENTRALSSH_STAGE_DIR"
  capture_gateway_state "final"
  python3 - <<'PY' "$CENTRALSSH_STAGE_DIR/audit.jsonl" >"$CENTRALSSH_STAGE_DIR/audit-check.txt"
import json
import sys
from collections import defaultdict

path = sys.argv[1]
last_ts = None
request_ids = defaultdict(int)
with open(path, "r", encoding="utf-8") as handle:
    for lineno, line in enumerate(handle, 1):
        entry = json.loads(line)
        ts = entry["timestamp"]
        if last_ts and ts < last_ts:
            print(f"ordering_regression line={lineno} prev={last_ts} now={ts}")
        last_ts = ts
        request_ids[entry.get("request_id")] += 1
print(f"request_ids={len(request_ids)}")
PY
  grep -q '^request_ids=' "$CENTRALSSH_STAGE_DIR/audit-check.txt" || fail_stage_case "audit_integrity" "audit integrity summary missing"
  pass_stage_case "audit_integrity" "audit JSONL parsed and ordering check recorded"
}
