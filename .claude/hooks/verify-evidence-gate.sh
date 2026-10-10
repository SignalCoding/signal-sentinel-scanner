#!/usr/bin/env bash
# PreToolUse hook (v1.8.1-cc) - WP1 Tier A.
# Blocks Write of verify-results.json when the proposed content violates the evidence contract.
# Exit 2 = block; stderr is fed back to Claude automatically (Claude Code hooks reference).
# v1.8.1-cc: JSON parsing via Python (jq is often absent on Windows Git Bash). If no Python is
# found the hook warns loudly and allows - Tier B (verify-gate.sh) then fails with the reason.
set -uo pipefail
INPUT="$(cat)"

PY=""; PY_ARGS=()
# Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  # Reject non-functional interpreters (e.g. the Windows Store python3 alias stub)
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
if [[ -z "$PY" ]]; then
  echo "verify-evidence-gate: WARNING - Python 3 not found; Tier A validation skipped." >&2
  exit 0
fi

FILE_PATH="$(printf '%s' "$INPUT" | pyc -c '
import json,sys
d=json.load(sys.stdin)
ti=d.get("tool_input") or {}
print(ti.get("file_path") or ti.get("path") or "")
' 2>/dev/null || echo "")"
# post-2.8.0: Claude Code on Windows can report a backslash path with a drive letter
# (C:\proj\_docs\ai\verify\verify-results.json). Normalise before the suffix match - without
# this the Tier A gate was silently bypassed on Windows.
FILE_PATH="${FILE_PATH//\\//}"
case "$FILE_PATH" in
  *"_docs/ai/verify/verify-results.json") : ;;
  *) exit 0 ;;   # not our file - allow
esac

CONTENT="$(printf '%s' "$INPUT" | pyc -c '
import json,sys
d=json.load(sys.stdin)
print((d.get("tool_input") or {}).get("content") or "", end="")
' 2>/dev/null || echo "")"
if [[ -z "$CONTENT" ]]; then
  # Edit/MultiEdit - full content not available pre-write; PostToolUse hook validates after.
  exit 0
fi

TMP="$(mktemp)"; trap 'rm -f "$TMP" "$TMP.err"' EXIT
printf '%s' "$CONTENT" > "$TMP"

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
if ! "$PROJECT_DIR/scripts/verify-gate.sh" --file "$TMP" 1>/dev/null 2>"$TMP.err"; then
  {
    echo "BLOCKED: this write to verify-results.json violates the evidence contract."
    cat "$TMP.err"
    echo "Fix: keep the criterion at FAIL, or produce evidence in _docs/ai/verify/evidence/ first and reference it. Prose is not evidence."
  } >&2
  exit 2
fi
exit 0
