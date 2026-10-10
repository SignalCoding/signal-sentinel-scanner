#!/usr/bin/env bash
# new-task-group.sh <TG-ID> "<title>" [--ui] - appends a task group skeleton with startedAt=now.
# Criteria are then added FAIL-first from the spec's EARS criterion IDs.
# v1.8.1-cc: JSON handling via Python (jq is often absent on Windows Git Bash).
# v1.10.0: --ui flags the group as UI-behavioural; the gate then requires *.uatresults.txt
#          interaction-test evidence (CONSTITUTION #24) - screenshots alone will not pass.
# v1.11.0: seeds "redBaseline": null (CONSTITUTION #26 - the gate refuses PASS criteria in a
#          group with no red baseline or exemption); refuses to create a task group unless
#          gate-state.json shows Gate 8 PASS (Rec 2). Override: --no-gates "<reason>" records
#          Gate 8 as EXEMPT with your reason - skips are legal, invisible skips are not.
# v3.0.0: --no-gates also stamps "reviewBy" (today + 14 days); verify-gate.sh --gates prints a
#          GATE-STATE NOTE once that date passes, so a skip cannot quietly become permanent.
#          Emits a TG-OPEN marker to _docs/ai/metrics/metrics.jsonl when the session-metrics
#          kit is installed (per-task-group timing in the metrics report).
# v3.3.0: --risk low|medium|high (default medium) records the tier the loop shape follows
#          (delegation-routing: low = coding-agent + checks + evaluator; high = finding
#          verification and a security report before PASS).
# v3.2.0: refuses a task-group ID that already exists (criteria had a duplicate check, groups
#          did not: two TG-11 rows made the gate judge the wrong one); records "baseCommit"
#          (HEAD at open, or null in a repo with no commit) so run-evaluator.sh judges the
#          group's whole diff rather than the last commit; the ID must match TG-<n>[A-Z]?
#          (TG-09, TG-10B) so helpers and the ledger agree on its shape.
set -euo pipefail
TG_ID="${1:?Usage: new-task-group.sh <TG-ID> \"<title>\" [--ui] [--risk low|medium|high] [--no-gates \"<reason>\"]}"
TITLE="${2:-}"
UI_FLAG="0"
RISK="medium"
NO_GATES_REASON=""
args=("${@:2}")
for i in "${!args[@]}"; do
  [[ "${args[$i]}" == "--ui" ]] && UI_FLAG="1"
  if [[ "${args[$i]}" == "--risk" ]]; then
    RISK="${args[$((i+1))]:-}"
    [[ "$RISK" =~ ^(low|medium|high)$ ]] || { echo "new-task-group: --risk takes low | medium | high." >&2; exit 1; }
  fi
  if [[ "${args[$i]}" == "--no-gates" ]]; then
    NO_GATES_REASON="${args[$((i+1))]:-}"
    [[ -z "$NO_GATES_REASON" ]] && { echo "new-task-group: --no-gates requires a written reason." >&2; exit 1; }
  fi
done
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$PROJECT_ROOT/_docs/ai/verify/verify-results.json"
[[ -f "$RESULTS" ]] || echo '{ "spec": "", "taskGroups": [] }' > "$RESULTS"
if [[ ! "$TG_ID" =~ ^TG-[0-9]{2,}[A-Z]?$ ]]; then
  echo "new-task-group: task-group ID '$TG_ID' is not TG-<nn>[A-Z] (TG-09, TG-10B)." >&2; exit 1
fi
BASE_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse --verify --quiet HEAD 2>/dev/null || true)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REVIEW_BY="$(date -u -d '+14 days' +%Y-%m-%d 2>/dev/null || date -u -v+14d +%Y-%m-%d 2>/dev/null || date -u +%Y-%m-%d)"

PY=""; PY_ARGS=()
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  # Reject non-functional interpreters (e.g. the Windows Store python3 alias stub)
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
[[ -z "$PY" ]] && { echo "new-task-group: Python 3 is required (python3/python/py not found)." >&2; exit 1; }

# v1.11.0 (Rec 2): implementation work only starts behind a signed-off gate sequence.
GATE_STATE="$PROJECT_ROOT/_docs/ai/verify/gate-state.json"
GATE_STATE_PATH="$GATE_STATE" NO_GATES_VAL="$NO_GATES_REASON" NOW_VAL="$NOW" REVIEW_BY_VAL="$REVIEW_BY" "$PY" "${PY_ARGS[@]}" - <<'GEOF'
import json, os, sys
path = os.environ["GATE_STATE_PATH"]; override = os.environ.get("NO_GATES_VAL", ""); now = os.environ["NOW_VAL"]
review_by = os.environ.get("REVIEW_BY_VAL", "")
def load():
    try:
        return json.load(open(path, encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None
data = load()
gates = {str(g.get("id")): g for g in (data or {}).get("gates", [])}
g8 = gates.get("8", {})
if g8.get("status") == "PASS" or g8.get("status") == "EXEMPT":
    sys.exit(0)
if not override:
    state = "absent" if data is None else g8.get("status", "absent")
    print(f"new-task-group: REFUSED - Gate 8 (Implementation Readiness) is {state}, not PASS.", file=sys.stderr)
    print("Run the gate sequence (skills/gate-sequence) and record it in _docs/ai/verify/gate-state.json", file=sys.stderr)
    print('(template: gate-state.example.json), or override loudly: new-task-group.sh <TG> "<title>" --no-gates "<reason>"', file=sys.stderr)
    sys.exit(1)
# Loud override: record Gate 8 EXEMPT with the reason.
if data is None:
    data = {"gates": []}
    g8 = None
else:
    g8 = gates.get("8")
if g8 is None:
    g8 = {"id": "8", "title": "Implementation Readiness"}
    data.setdefault("gates", []).append(g8)
g8.update({"status": "EXEMPT", "note": override, "timestamp": now, "reviewBy": review_by})
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2); fh.write("\n")
print(f"new-task-group: Gate 8 recorded EXEMPT ({override}; reviewBy {review_by}) - visible on every --gates run.", file=sys.stderr)
GEOF


RESULTS_PATH="$RESULTS" TG_ID_VAL="$TG_ID" TITLE_VAL="$TITLE" NOW_VAL="$NOW" UI_VAL="$UI_FLAG" BASE_VAL="$BASE_COMMIT" RISK_VAL="$RISK" \
"$PY" "${PY_ARGS[@]}" -c '
import json, os, sys
path = os.environ["RESULTS_PATH"]
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)
tg_id = os.environ["TG_ID_VAL"]
if any(g.get("id") == tg_id for g in data.get("taskGroups", [])):
    print(f"new-task-group: {tg_id} already exists in verify-results.json - task-group IDs are unique; nothing written.", file=sys.stderr)
    sys.exit(1)
group = {
    "id": tg_id,
    "title": os.environ["TITLE_VAL"],
    "startedAt": os.environ["NOW_VAL"],
    "baseCommit": os.environ.get("BASE_VAL") or None,
    "risk": os.environ.get("RISK_VAL") or "medium",
    "redBaseline": None,
    "criteria": [],
}
if os.environ.get("UI_VAL") == "1":
    group["ui"] = True
data.setdefault("taskGroups", []).append(group)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
'
# v3.0.0: session-metrics marker (no-op when the kit is not installed; never fails the script)
if [[ -f "$PROJECT_ROOT/scripts/metrics/hook.sh" ]]; then
  bash "$PROJECT_ROOT/scripts/metrics/hook.sh" TGOpen "$TG_ID" >/dev/null 2>&1 || true
fi
if [[ "$UI_FLAG" == "1" ]]; then
  echo "Added $TG_ID (startedAt=$NOW, ui=true). Interaction-test evidence (*.uatresults.txt) AND one deployed-environment capture (<ID>.live.*) will be required."
else
  echo "Added $TG_ID (startedAt=$NOW, risk=$RISK). Add criteria FAIL-first with their spec IDs."
fi
