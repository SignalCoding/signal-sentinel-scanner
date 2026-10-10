#!/usr/bin/env bash
#
# gate-stop.sh (v1.9.0-cc)
#
# Stop hook for Claude Code. Fires when the main agent finishes responding.
# Runs the project's evidence gate (scripts/verify-gate.sh). If the gate fails,
# exits 2 to BLOCK the stop and feeds the reason back to Claude, so a turn cannot
# end while the completion contract is violated.
#
# Registered in each template's .claude/settings.json under the "Stop" event.
#
# Reads JSON from stdin (the hook payload). Uses Python for JSON (jq is often
# absent on Windows Git Bash), matching the other v1.8.1-cc hooks.
#
# Safety / loop guard:
#   - If stop_hook_active is true (Claude is already continuing because of a prior
#     block from this hook), exit 0 so we never loop forever.
#   - If the project has no verify-results.json, exit 0 (project is not under the
#     v1.7+ contract; nothing to gate).
#
# Exit 0 = allow the stop. Exit 2 = block the stop (reason on stderr).
#
# v1.11.0: degraded environment (no Python 3) now fails CLOSED while a
# completion contract is active (verify-results.json present), with the loop
# guard preserved via a raw grep for stop_hook_active. Without a contract it
# fails open loudly.

set -uo pipefail

INPUT=$(cat)

PY=""; PY_ARGS=()
# Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
if [[ -z "$PY" ]]; then
  # Degraded-environment policy (v1.11.0): gate-stop stays FAIL-CLOSED.
  # Without a JSON engine the evidence gate cannot be verified, and this hook's
  # entire job is to stop a turn ending on an unverifiable completion claim.
  # The loop guard is preserved with a raw scan of the payload, so a degraded
  # block can never loop forever.
  if printf '%s' "$INPUT" | grep -qE '"stop_hook_active"[[:space:]]*:[[:space:]]*true'; then
    exit 0
  fi
  if [[ -f "${CLAUDE_PROJECT_DIR:-$PWD}/_docs/ai/verify/verify-results.json" ]]; then
    echo "STOP BLOCKED by gate-stop (DEGRADED mode): Python 3 not found, so the evidence gate cannot be verified while a completion contract is active (verify-results.json present)." >&2
    echo "Install Python 3 (python3/python/py) and re-run the gate. Fail-closed is intentional: a turn must not end on an unverifiable completion claim." >&2
    exit 2
  fi
  echo "gate-stop: WARNING - Python 3 not found; no completion contract detected, stop gate skipped." >&2
  exit 0
fi

# stop_hook_active guards against an infinite block loop.
STOP_ACTIVE="$(printf '%s' "$INPUT" | pyc -c '
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    print("false"); sys.exit(0)
print("true" if d.get("stop_hook_active") else "false")
' 2>/dev/null || echo "false")"

if [[ "$STOP_ACTIVE" == "true" ]]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$PWD}"
GATE="$PROJECT_DIR/scripts/verify-gate.sh"
RESULTS="$PROJECT_DIR/_docs/ai/verify/verify-results.json"

# No contract in this project -> nothing to gate.
[[ -f "$RESULTS" ]] || exit 0
# v1.11.1 (review H1): a contract IS active here - a missing validator must BLOCK, not
# silently disable the gate (deleting verify-gate.sh must never turn the Stop gate off).
if [[ ! -f "$GATE" ]]; then
  {
    echo "STOP BLOCKED by gate-stop: verify-results.json exists (completion contract active) but"
    echo "scripts/verify-gate.sh is MISSING. The gate cannot run, so this turn cannot end on a"
    echo "completion claim. Restore the validator (re-run bootstrap or copy it from the master"
    echo "library) - do not delete the contract to get past this."
  } >&2
  exit 2
fi

if OUT="$(bash "$GATE" 2>&1)"; then
  exit 0
fi

{
  echo "STOP BLOCKED by gate-stop: the evidence gate is failing, so this turn cannot end on a completion claim."
  echo "Fix the failing criteria (produce evidence, or set BLOCKED with a disposition) until verify-gate.sh exits zero."
  echo ""
  echo "$OUT"
} >&2
exit 2
