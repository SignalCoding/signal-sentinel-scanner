#!/usr/bin/env bash
# run-converge.sh (v2.3.0, review B-4) - repo-wide drift sweep: does the codebase still
# match its living spec and CONSTITUTION? The INVERSE of the per-task-group evaluator:
# the evaluator judges one change as it lands; converge periodically re-judges the WHOLE
# system for slow rot between task groups (weakened invariants, dead capabilities,
# undocumented behaviour).
#
# Usage: bash scripts/run-converge.sh
#
# Mechanics mirror run-evaluator.sh: a FRESH claude -p process (never the build session -
# self-review reliably overrates its own work), prompt passed via stdin (argv limits),
# read-only duty, report written by the ORCHESTRATOR from the returned content to
# _docs/ai/logs/converge-report-<date>.md. Findings become gap-closure tasks, not silent
# fixes. Requires the Claude CLI.
# v3.0.0: refuses to sweep a branch other than the integration branch (main/master) unless
# --branch-ok is passed - a converge report written against a half-finished feature branch
# judged the wrong tree and its "gaps" were the work in progress (harvest 2026-09).
set -euo pipefail
die() { echo "run-converge: FATAL: $*" >&2; exit 1; }
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BRANCH_OK=0; [[ "${1:-}" == "--branch-ok" ]] && BRANCH_OK=1
CUR_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "?")"
if [[ "$BRANCH_OK" == "0" && "$CUR_BRANCH" != "main" && "$CUR_BRANCH" != "master" ]]; then
  die "current branch is '$CUR_BRANCH', not main/master - converge judges the integrated tree. Switch branch, or pass --branch-ok to sweep this branch deliberately (the report header will name it)."
fi
if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
  echo "run-converge: NOTE - working tree has uncommitted changes; the sweep judges files as they are on disk, not the last commit." >&2
fi

command -v claude >/dev/null 2>&1 || die "claude CLI not found - converge runs in a fresh claude -p process by design"
[[ -f _docs/ai/SYSTEM-SPEC.md ]] || die "_docs/ai/SYSTEM-SPEC.md missing"
[[ -f CONSTITUTION.md ]] || die "CONSTITUTION.md missing"

CAP_COUNT="$(grep -c '^| [a-z0-9]' _docs/ai/SYSTEM-SPEC.md || true)"
if [[ "$CAP_COUNT" -eq 0 ]]; then
  echo "run-converge: SYSTEM-SPEC has no capability rows yet (nothing archived)." >&2
  echo "Converge is meaningful after the first archive-spec.sh run. Nothing to do." >&2
  exit 0
fi

DATE="$(date +%Y-%m-%d)"
OUT="_docs/ai/logs/converge-report-$DATE.md"

{
  echo "# Converge report - $DATE - branch: $CUR_BRANCH - commit: $(git rev-parse --short HEAD 2>/dev/null || echo '?')"
  echo ""
} > "$OUT"

{
  echo "You are the CONVERGE sweep - a fresh-context, read-only assessor. You have not seen"
  echo "any build session. Judge the CURRENT codebase against (1) the living system spec and"
  echo "(2) the CONSTITUTION invariants below. Duties, in order:"
  echo "1. For EACH capability row: does the code still deliver it? Cite file:line evidence"
  echo "   per verdict (DELIVERED / DEGRADED / MISSING). No praise; evidence only."
  echo "2. For each CONSTITUTION invariant marked [E] or [S]: find one concrete violation or"
  echo "   state 'no violation found' - never 'looks fine'."
  echo "3. BEHAVIOUR NOT IN THE SPEC: list user-visible capabilities the code clearly has"
  echo "   that no capability row covers (spec rot runs both directions)."
  echo "4. Output format: '## Gap-closure tasks' - a numbered list, each item actionable as"
  echo "   a delegation brief. If none: 'CONVERGED: no gaps found.' Findings without"
  echo "   file:line evidence are ADVISORY and must be labelled."
  echo ""
  echo "=== LIVING SYSTEM SPEC ==="
  cat _docs/ai/SYSTEM-SPEC.md
  echo ""
  echo "=== CONSTITUTION ==="
  cat CONSTITUTION.md
  echo ""
  echo "=== REPO FILE LISTING (read files yourself as needed) ==="
  git ls-files 2>/dev/null || find . -name .git -prune -o -type f -print | sed 's|^\./||'
} | claude -p --permission-mode plan >> "$OUT" \
  || { rm -f "$OUT"; die "claude -p failed - report not written"; }

echo "run-converge: report written to $OUT"
echo "Next: turn its '## Gap-closure tasks' into delegation briefs (they do NOT bypass the"
echo "normal spec -> red -> green -> gate loop; converge FINDS work, it never lands work)."
