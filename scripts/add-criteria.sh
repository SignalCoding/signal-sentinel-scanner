#!/usr/bin/env bash
# add-criteria.sh <TG-ID> <CRIT-ID> "<EARS text>" [<CRIT-ID> "<EARS text>" ...]
# v3.0.0 - appends criteria FAIL-first to a task group in verify-results.json, one Python
# write, no hand-editing of the contract. Every criterion lands with status FAIL and an empty
# evidence list; PASS is set ONLY by scripts/set-criterion.sh against evidence files.
#
# Why a script: hand-edited contracts were the source of three field defects (a criterion
# pasted twice, a "status": "pending" that the gate does not know, a group whose criteria were
# never written at all - the vacuous gate). Scripts cannot make those mistakes.
#
# Refuses: unknown task group; duplicate criterion ID (anywhere in the file); empty text;
# an odd number of ID/text arguments. Nothing is written on any refusal.
set -euo pipefail
USAGE='Usage: add-criteria.sh <TG-ID> <CRIT-ID> "<EARS text>" [<CRIT-ID> "<EARS text>" ...]'
TG_ID="${1:?$USAGE}"; shift
[[ $# -ge 2 ]] || { echo "$USAGE" >&2; exit 1; }
[[ $(( $# % 2 )) -eq 0 ]] || { echo "add-criteria: arguments must be <CRIT-ID> \"<text>\" pairs (got an odd count)." >&2; echo "$USAGE" >&2; exit 1; }
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$PROJECT_ROOT/_docs/ai/verify/verify-results.json"
[[ -f "$RESULTS" ]] || { echo "add-criteria: $RESULTS not found - create the task group first (scripts/new-task-group.sh)." >&2; exit 1; }

PY=""; PY_ARGS=()
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
[[ -z "$PY" ]] && { echo "add-criteria: Python 3 is required (python3/python/py not found)." >&2; exit 1; }

RESULTS_PATH="$RESULTS" TG_ID_VAL="$TG_ID" "$PY" "${PY_ARGS[@]}" - "$@" <<'PYEOF'
import json, os, sys, re
path = os.environ["RESULTS_PATH"]; tg_id = os.environ["TG_ID_VAL"]
args = sys.argv[1:]
pairs = list(zip(args[0::2], args[1::2]))
data = json.load(open(path, encoding="utf-8"))
groups = [tg for tg in data.get("taskGroups", []) if tg.get("id") == tg_id]
if not groups:
    print(f"add-criteria: task group '{tg_id}' not found in verify-results.json (scripts/new-task-group.sh creates it).", file=sys.stderr); sys.exit(1)
tg = groups[0]
existing = {c.get("id") for g in data.get("taskGroups", []) for c in g.get("criteria", [])}
ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z0-9-]+$")
errors = []
seen = set()
for cid, text in pairs:
    cid = cid.strip(); text = text.strip()
    if not ID_RE.match(cid):
        errors.append(f"'{cid}' is not a spec-style criterion ID (e.g. AUTH-C1, PAY-C2-EXTERNAL-SERVICE)")
    if cid in existing or cid in seen:
        errors.append(f"'{cid}' already exists (criterion IDs are unique across the whole contract)")
    if not text:
        errors.append(f"'{cid}' has empty text (paste the EARS criterion from the spec)")
    seen.add(cid)
if errors:
    for e in errors: print(f"add-criteria: REFUSED - {e}", file=sys.stderr)
    sys.exit(1)
for cid, text in pairs:
    tg.setdefault("criteria", []).append({"id": cid.strip(), "text": text.strip(), "status": "FAIL", "evidence": []})
with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2); fh.write("\n")
print(f"add-criteria: {len(pairs)} criterion/criteria added to {tg_id} as FAIL: " + ", ".join(c for c, _ in pairs))
print("Next: red baseline (scripts/set-criterion.sh --red <TG-ID> <file>), then implement, then set-criterion.sh <TG-ID> <CRIT-ID> PASS <evidence>...")
PYEOF
