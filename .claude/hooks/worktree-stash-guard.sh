#!/usr/bin/env bash
# worktree-stash-guard.sh - PreToolUse hook (v1.10.0, findings 5.1)
# Blocks `git stash` when executed inside a git WORKTREE (not the primary tree).
# The stash stack is repository-global across all worktrees: two concurrent
# worktree-isolated agents that stash/pop will silently corrupt each other's
# state (B's pop applies A's stash; no error, just wrong files in wrong trees).
#
# PreToolUse contract: read tool input JSON on stdin; exit 0 = allow,
# exit 2 = BLOCK with stderr shown to the model as the reason.
# v1.11.0: degraded environment (no Python 3) now fails open LOUDLY (stderr
# warning naming the missing engine) instead of silently.
set -uo pipefail

PY=""; PY_ARGS=()
# Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
# Degraded-environment policy (v1.11.0): fail-open LOUD. The guard is a safety
# net, not a work-stopper, but the operator must know it is offline.
if [[ -z "$PY" ]]; then
  echo "worktree-stash-guard: WARNING - Python 3 not found (tried python3/python/py); stash guard SKIPPED." >&2
  echo "worktree-stash-guard: 'git stash' is currently UNGUARDED in worktree sessions - install Python 3 to restore the guard." >&2
  exit 0
fi

CMD="$(pyc -c '
import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get("tool_input",{}).get("command",""))
except Exception:
    print("")
' 2>/dev/null || true)"

# Match a git stash invocation (any subcommand), tolerating flags between git and stash.
# v1.11.2 (re-review): the old matcher required flag-only tokens between git and stash, so
# `git -C ../wt1 stash` (flag WITH argument) was not even recognised. Match `stash` anywhere in
# the same shell segment as `git` - slight overmatch (e.g. `git log --grep stash`) is an
# acceptable loud block; a missed stash is not.
if ! echo "$CMD" | grep -qE '(^|[;&|[:space:]])git[[:space:]]([^;|&]*[[:space:]])?stash([[:space:]]|$)'; then
  exit 0
fi

# v1.11.2 (re-review): honour `git -C <path>` - probing only our own CWD let
# `git -C ../wt stash` evade the guard. Extract the -C target and probe THERE.
C_TARGET="$(printf '%s' "$CMD" | sed -nE 's/.*git[[:space:]]+(-[^C[:space:]][^[:space:]]*[[:space:]]+)*-C[[:space:]]+("([^"]+)"|'"'"'([^'"'"']+)'"'"'|([^[:space:]]+)).*/\3\4\5/p' | head -1)"
GIT_PROBE=(git)
[[ -n "$C_TARGET" ]] && GIT_PROBE=(git -C "$C_TARGET")
# Worktree detection: in a linked worktree, --git-dir differs from --git-common-dir.
GIT_DIR="$("${GIT_PROBE[@]}" rev-parse --git-dir 2>/dev/null || true)"
COMMON_DIR="$("${GIT_PROBE[@]}" rev-parse --git-common-dir 2>/dev/null || true)"
IS_WORKTREE=0
if [[ -n "$GIT_DIR" && -n "$COMMON_DIR" && "$GIT_DIR" != "$COMMON_DIR" ]]; then
  IS_WORKTREE=1
fi
# Orchestrator-set marker also counts (set when spawning worktree agents).
[[ "${AIAGENT_WORKTREE:-}" == "1" ]] && IS_WORKTREE=1

if [[ "$IS_WORKTREE" == "1" ]]; then
  echo "BLOCKED: git stash is repository-global across ALL worktrees - stashing here can" >&2
  echo "corrupt parallel agents' state (another agent's pop may apply YOUR stash)." >&2
  echo "Instead: commit your changes on this worktree's branch (the merge step consumes" >&2
  echo "committed branches), or take a file-copy backup (cp -r <paths> <scratch-dir>)." >&2
  echo "See skills/delegation-routing (Worktree-Parallel Orchestration Doctrine)." >&2
  exit 2
fi

exit 0
