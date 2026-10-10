#!/usr/bin/env bash
# log-decision.sh "<decision>" [--why "<reason>"] [--evidence "<file or fact>"] [--owner-pending]
#                 [--resolves <n>]
# v3.0.0 - appends the next numbered entry to _docs/ai/decision-log.md (one list, monotonically
# increasing, never renumbered). Hand-appended entries were mis-numbered or dropped the
# OWNER-PENDING marker in two field projects; the script cannot.
#   --owner-pending   marks the entry as waiting on the human (greppable OWNER-PENDING)
#   --resolves <n>    rewrites entry n's marker to "was OWNER-PENDING" and links back to it
set -euo pipefail
USAGE='Usage: log-decision.sh "<decision>" [--why "<reason>"] [--evidence "<ref>"] [--owner-pending] [--resolves <n>]'
DECISION="${1:?$USAGE}"; shift
WHY=""; EVIDENCE=""; PENDING=0; RESOLVES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --why) WHY="${2:?--why requires text}"; shift 2 ;;
    --evidence) EVIDENCE="${2:?--evidence requires text}"; shift 2 ;;
    --owner-pending) PENDING=1; shift ;;
    --resolves) RESOLVES="${2:?--resolves requires an entry number}"; shift 2 ;;
    *) echo "log-decision: unknown argument '$1'" >&2; echo "$USAGE" >&2; exit 1 ;;
  esac
done
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$PROJECT_ROOT/_docs/ai/decision-log.md"
[[ -f "$LOG" ]] || { echo "log-decision: $LOG not found (bootstrap delivers it)." >&2; exit 1; }

PY=""; PY_ARGS=()
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
[[ -z "$PY" ]] && { echo "log-decision: Python 3 is required (python3/python/py not found)." >&2; exit 1; }

LOG_PATH="$LOG" DECISION_VAL="$DECISION" WHY_VAL="$WHY" EVIDENCE_VAL="$EVIDENCE" PENDING_VAL="$PENDING" RESOLVES_VAL="$RESOLVES" \
"$PY" "${PY_ARGS[@]}" - <<'PYEOF'
import os, re, sys
from datetime import date
path = os.environ["LOG_PATH"]
text = open(path, encoding="utf-8").read()
entries = re.findall(r"^(\d+)\.\s", text, re.M)
nxt = (max(int(n) for n in entries) + 1) if entries else 1
resolves = os.environ.get("RESOLVES_VAL", "").strip()
if resolves:
    if not re.search(rf"^{re.escape(resolves)}\.\s", text, re.M):
        print(f"log-decision: entry {resolves} does not exist; nothing written.", file=sys.stderr); sys.exit(1)
    # rewrite that entry's marker (only the first OWNER-PENDING inside the entry line)
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(resolves)}\.\s", line) and "OWNER-PENDING" in line and "was OWNER-PENDING" not in line:
            lines[i] = line.replace("OWNER-PENDING", "was OWNER-PENDING", 1); break
    text = "\n".join(lines)
def sentence(t):
    t = t.strip(); return t if t.endswith((".", "!", "?")) else t + "."
parts = [f"({date.today().isoformat()}) {sentence(os.environ['DECISION_VAL'])}"]
if os.environ.get("WHY_VAL", "").strip(): parts.append("Why: " + sentence(os.environ["WHY_VAL"]))
if os.environ.get("EVIDENCE_VAL", "").strip(): parts.append("Evidence: " + sentence(os.environ["EVIDENCE_VAL"]))
if resolves: parts.append(f"Resolves #{resolves}.")
if os.environ.get("PENDING_VAL") == "1": parts.append("OWNER-PENDING")
entry = f"{nxt}. " + " ".join(parts)
if not text.endswith("\n"): text += "\n"
text += entry + "\n"
open(path, "w", encoding="utf-8").write(text)
print(f"log-decision: appended entry {nxt}" + (" (OWNER-PENDING)" if os.environ.get("PENDING_VAL") == "1" else "") + (f"; entry {resolves} marked resolved" if resolves else ""))
PYEOF
