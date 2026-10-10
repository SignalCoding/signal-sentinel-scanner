#!/usr/bin/env bash
# set-criterion.sh - the ONLY sanctioned way to move a criterion's status (v3.0.0).
#
#   set-criterion.sh <TG-ID> <CRIT-ID> PASS <evidence-file> [<evidence-file> ...]
#   set-criterion.sh <TG-ID> <CRIT-ID> FAIL
#   set-criterion.sh <TG-ID> <CRIT-ID> BLOCKED <GATE-TOKEN> "<disposition>"
#   set-criterion.sh --red <TG-ID> <red-baseline-file> | --red-exempt <TG-ID> "<reason>"
#   set-criterion.sh <TG-ID> <CRIT-ID> --addendum <YYYY-MM-DD>     (records addendumAt; also allows the test change)
#   set-criterion.sh --allow-test-change <TG-ID> "<brief reference>"  (records allowTestChange: a spec-mandated
#                                                                      test change the gate would otherwise refuse as [TEST-MODIFIED])
#   set-criterion.sh --risk <TG-ID> low|medium|high                 (records the group's risk tier)
#
# Transactional: the change is written, `scripts/verify-gate.sh --tg <TG-ID>` runs, and on any
# violation the previous contract is restored byte-for-byte and the gate's reasons are printed.
# A PASS therefore cannot land without evidence that exists, is non-empty, matches the allowed
# patterns and postdates the task group start - the same bar as the pre-commit gate, applied
# at the moment of the claim rather than at the next commit.
#
# Evidence files are named relative to _docs/ai/verify/evidence/. When the session-metrics kit
# is installed, the first moment a task group has no FAIL left emits a TG-CLOSE marker.
set -euo pipefail
USAGE='Usage: set-criterion.sh <TG-ID> <CRIT-ID> PASS <evidence>... | FAIL | BLOCKED <GATE> "<disposition>" | --addendum <date>
       set-criterion.sh --red <TG-ID> <red-baseline-file> | --red-exempt <TG-ID> "<reason>"
       set-criterion.sh --allow-test-change <TG-ID> "<brief reference>" | --risk <TG-ID> low|medium|high'
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$PROJECT_ROOT/_docs/ai/verify/verify-results.json"
[[ -f "$RESULTS" ]] || { echo "set-criterion: $RESULTS not found." >&2; exit 1; }

PY=""; PY_ARGS=()
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
[[ -z "$PY" ]] && { echo "set-criterion: Python 3 is required (python3/python/py not found)." >&2; exit 1; }

MODE="criterion"
case "${1:-}" in
  --red) MODE="red"; TG_ID="${2:?$USAGE}"; RED_FILE="${3:?$USAGE}" ;;
  --red-exempt) MODE="red-exempt"; TG_ID="${2:?$USAGE}"; RED_REASON="${3:?$USAGE}" ;;
  --allow-test-change) MODE="allow-test-change"; TG_ID="${2:?$USAGE}"; RED_REASON="${3:?$USAGE}" ;;
  --risk) MODE="risk"; TG_ID="${2:?$USAGE}"; RED_REASON="${3:?$USAGE}" ;;
  "") echo "$USAGE" >&2; exit 1 ;;
  *) TG_ID="$1"; CRIT_ID="${2:?$USAGE}"; ACTION="${3:?$USAGE}"; shift 3 ;;
esac

BACKUP="$(mktemp "$PROJECT_ROOT/_docs/ai/verify/.verify-results.XXXXXX")"
cp "$RESULTS" "$BACKUP"
restore() { cp "$BACKUP" "$RESULTS"; rm -f "$BACKUP"; }

set +e
CLOSE_STATE="$(RESULTS_PATH="$RESULTS" MODE_VAL="$MODE" TG_ID_VAL="$TG_ID" CRIT_ID_VAL="${CRIT_ID:-}" ACTION_VAL="${ACTION:-}" \
RED_FILE_VAL="${RED_FILE:-}" RED_REASON_VAL="${RED_REASON:-}" \
"$PY" "${PY_ARGS[@]}" - "$@" <<'PYEOF'
import json, os, sys
from datetime import date
path = os.environ["RESULTS_PATH"]; mode = os.environ["MODE_VAL"]; tg_id = os.environ["TG_ID_VAL"]
data = json.load(open(path, encoding="utf-8"))
groups = [tg for tg in data.get("taskGroups", []) if tg.get("id") == tg_id]
if not groups:
    print(f"set-criterion: task group '{tg_id}' not found.", file=sys.stderr); sys.exit(1)
tg = groups[0]
was_all_green = bool(tg.get("criteria")) and all(c.get("status") in ("PASS", "BLOCKED") for c in tg.get("criteria", []))
if mode == "red":
    tg["redBaseline"] = os.environ["RED_FILE_VAL"].strip()
elif mode == "red-exempt":
    tg["redBaseline"] = {"exempt": os.environ["RED_REASON_VAL"].strip()}
elif mode == "allow-test-change":
    tg["allowTestChange"] = os.environ["RED_REASON_VAL"].strip()
elif mode == "risk":
    lvl = os.environ["RED_REASON_VAL"].strip().lower()
    if lvl not in ("low", "medium", "high"):
        print("set-criterion: --risk takes low | medium | high.", file=sys.stderr); sys.exit(1)
    tg["risk"] = lvl
else:
    cid = os.environ["CRIT_ID_VAL"]; action = os.environ["ACTION_VAL"]; args = sys.argv[1:]
    crits = [c for c in tg.get("criteria", []) if c.get("id") == cid]
    if not crits:
        print(f"set-criterion: criterion '{cid}' not found in {tg_id} (scripts/add-criteria.sh adds it FAIL-first).", file=sys.stderr); sys.exit(1)
    c = crits[0]
    if action == "PASS":
        if not args:
            print("set-criterion: PASS requires at least one evidence file (relative to _docs/ai/verify/evidence/).", file=sys.stderr); sys.exit(1)
        c["status"] = "PASS"; c["evidence"] = [a.strip() for a in args]
        c.pop("gate", None); c.pop("disposition", None)
    elif action == "FAIL":
        c["status"] = "FAIL"; c["evidence"] = []
        c.pop("gate", None); c.pop("disposition", None)
    elif action == "BLOCKED":
        if len(args) < 2:
            print('set-criterion: BLOCKED requires <GATE-TOKEN> "<disposition>".', file=sys.stderr); sys.exit(1)
        c["status"] = "BLOCKED"; c["evidence"] = []; c["gate"] = args[0].strip(); c["disposition"] = args[1].strip()
    elif action == "--addendum":
        if not args:
            print("set-criterion: --addendum requires a YYYY-MM-DD date.", file=sys.stderr); sys.exit(1)
        try: date.fromisoformat(args[0][:10])
        except ValueError:
            print(f"set-criterion: '{args[0]}' is not an ISO date.", file=sys.stderr); sys.exit(1)
        c["addendumAt"] = args[0][:10]
        # an addendum changes a criterion, and the test asserting the old wording changes with it
        tg["allowTestChange"] = f"addendum {args[0][:10]} on {cid}" if not (tg.get("allowTestChange") or "").strip() else tg["allowTestChange"]
    else:
        print(f"set-criterion: unknown action '{action}' (PASS | FAIL | BLOCKED | --addendum).", file=sys.stderr); sys.exit(1)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2); fh.write("\n")
now_all_green = bool(tg.get("criteria")) and all(c.get("status") in ("PASS", "BLOCKED") for c in tg.get("criteria", []))
print("CLOSE" if (now_all_green and not was_all_green) else "OPEN")
PYEOF
)"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then restore; exit 1; fi

# Transaction: the gate decides whether the edit stands. Metadata modes (risk tier, test-change
# allowance) claim nothing and are recorded without the gate run, so an allowance can be written
# while the gate is red for the reason the allowance addresses.
if [[ "$MODE" == "risk" || "$MODE" == "allow-test-change" ]]; then
  rm -f "$BACKUP"
elif ! bash "$PROJECT_ROOT/scripts/verify-gate.sh" --tg "$TG_ID" >/dev/null 2>"$BACKUP.err"; then
  echo "set-criterion: REFUSED - the evidence gate rejects this change; contract restored:" >&2
  sed 's/^/  /' "$BACKUP.err" >&2
  rm -f "$BACKUP.err"; restore; exit 1
fi
rm -f "$BACKUP.err" "$BACKUP" 2>/dev/null || true

case "$MODE" in
  red) echo "set-criterion: $TG_ID red baseline recorded: $RED_FILE (commit it on its own BEFORE any green evidence)." ;;
  red-exempt) echo "set-criterion: $TG_ID red baseline EXEMPT: $RED_REASON (printed loudly at every gate pass)." ;;
  allow-test-change) echo "set-criterion: $TG_ID test change allowed: $RED_REASON (printed as [TEST-CHANGE-ALLOWED] at every gate pass)." ;;
  risk) echo "set-criterion: $TG_ID risk tier: $RED_REASON." ;;
  *) echo "set-criterion: $TG_ID/$CRIT_ID -> $ACTION ${*:-}" ;;
esac

# session-metrics marker: the first moment the group has no FAIL left (no-op without the kit)
if [[ -f "$PROJECT_ROOT/scripts/metrics/hook.sh" && "$CLOSE_STATE" == "CLOSE" ]]; then
  bash "$PROJECT_ROOT/scripts/metrics/hook.sh" TGClose "$TG_ID" >/dev/null 2>&1 || true
fi
