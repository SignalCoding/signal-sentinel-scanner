#!/usr/bin/env bash
# log-delegation.sh <task-slug> <phase> <agent> <model> "<reason>" [--tokens <in> <out>]
#                   [--classification "<surface>, <risk>, <complexity>, <diff>, <compliance>"]
#                   [--response confirm|override|auto] [--proposed <agent>] [--outcome dispatched|aborted]
#                   [--class <task class>] [--effort low|medium|high|max] [--retries <n>] [--elapsed <seconds>]
# v3.3.0 - the four optional fields are the per-delegation metrics the session-metrics report reads
# from the ledger (tokens per verified accepted change needs retries and class, not a guess).
# v3.0.0 - writes the REASONED half of the delegation audit trail (delegation-routing Step 7)
# to _docs/ai/logs/<task-slug>_delegation.md in the exact entry shape the evaluator
# cross-checks, and - when --tokens is given - appends a ledger row with real token counts to
# _docs/ai/logs/delegation-ledger.log, replacing the "?" the hook records when the Task
# payload carries no usage figures (harvest 2026-09: every ledger row on two projects was
# "? | ?", so spend was an event count, never a cost). Token counts come from the sub-agent's
# closing message or the session-metrics report; the row is tagged "manual" so nobody
# mistakes it for a hook capture.
set -euo pipefail
USAGE='Usage: log-delegation.sh <task-slug> <phase> <agent> <model> "<reason>" [--tokens <in> <out>] [--classification "<...>"] [--response confirm|override|auto] [--proposed <agent>] [--outcome dispatched|aborted] [--class <task class>] [--effort low|medium|high|max] [--retries <n>] [--elapsed <seconds>]'
SLUG="${1:?$USAGE}"; PHASE="${2:?$USAGE}"; AGENT="${3:?$USAGE}"; MODEL="${4:?$USAGE}"; REASON="${5:?$USAGE}"; shift 5
T_IN=""; T_OUT=""; CLASS="(not recorded)"; RESPONSE="confirm"; PROPOSED="$AGENT"; OUTCOME="dispatched"
T_CLASS=""; T_EFFORT=""; T_RETRIES=""; T_ELAPSED=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tokens) T_IN="${2:?--tokens requires <in> <out>}"; T_OUT="${3:?--tokens requires <in> <out>}"; shift 3 ;;
    --classification) CLASS="${2:?}"; shift 2 ;;
    --response) RESPONSE="${2:?}"; shift 2 ;;
    --proposed) PROPOSED="${2:?}"; shift 2 ;;
    --outcome) OUTCOME="${2:?}"; shift 2 ;;
    --class) T_CLASS="${2:?--class requires a value}"; shift 2 ;;
    --effort) T_EFFORT="${2:?--effort requires low|medium|high|max}"; shift 2 ;;
    --retries) T_RETRIES="${2:?--retries requires <n>}"; shift 2 ;;
    --elapsed) T_ELAPSED="${2:?--elapsed requires <seconds>}"; shift 2 ;;
    *) echo "log-delegation: unknown argument '$1'" >&2; echo "$USAGE" >&2; exit 1 ;;
  esac
done
if [[ -n "$T_EFFORT" ]]; then case "$T_EFFORT" in low|medium|high|max) ;; *) echo "log-delegation: --effort must be low | medium | high | max." >&2; exit 1 ;; esac; fi
[[ -z "$T_RETRIES" || "$T_RETRIES" =~ ^[0-9]+$ ]] || { echo "log-delegation: --retries must be an integer." >&2; exit 1; }
[[ -z "$T_ELAPSED" || "$T_ELAPSED" =~ ^[0-9]+$ ]] || { echo "log-delegation: --elapsed must be whole seconds." >&2; exit 1; }
[[ "$T_CLASS" == *"|"* ]] && { echo "log-delegation: --class must not contain '|'." >&2; exit 1; }
METRICS=""
[[ -n "$T_CLASS" ]] && METRICS="${METRICS:+$METRICS }class=$T_CLASS"
[[ -n "$T_EFFORT" ]] && METRICS="${METRICS:+$METRICS }effort=$T_EFFORT"
[[ -n "$T_RETRIES" ]] && METRICS="${METRICS:+$METRICS }retries=$T_RETRIES"
[[ -n "$T_ELAPSED" ]] && METRICS="${METRICS:+$METRICS }elapsed=${T_ELAPSED}s"
case "$PHASE" in test|implement|security-review|review|research) ;; *) echo "log-delegation: phase must be test | implement | security-review | review | research (got '$PHASE')." >&2; exit 1 ;; esac
case "$OUTCOME" in dispatched|aborted) ;; *) echo "log-delegation: outcome must be dispatched | aborted." >&2; exit 1 ;; esac
if [[ -n "$T_IN" ]]; then
  [[ "$T_IN" =~ ^[0-9]+$ && "$T_OUT" =~ ^[0-9]+$ ]] || { echo "log-delegation: --tokens values must be integers." >&2; exit 1; }
fi
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$PROJECT_ROOT/_docs/ai/logs"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/${SLUG}_delegation.md"
LEDGER="$LOG_DIR/delegation-ledger.log"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Correction count: one more than the number of previous entries for the same agent in this
# log that were dispatched (a re-prompt of the same agent is a correction, by definition).
PREV="$(grep -c "^- \*\*Actual agent:\*\* $AGENT\$" "$LOG" 2>/dev/null || true)"
PREV="${PREV:-0}"

[[ -f "$LOG" ]] || printf '# Delegation log - %s\n\nReasoned half of the audit trail (delegation-routing Step 7). Machine half: delegation-ledger.log.\n' "$SLUG" > "$LOG"
{
  echo ""
  echo "## $TS"
  echo ""
  echo "- **Phase:** $PHASE"
  echo "- **Proposed agent:** $PROPOSED"
  echo "- **Actual agent:** $AGENT"
  echo "- **Model:** $MODEL"
  echo "- **User response:** $RESPONSE"
  echo "- **Classification:** $CLASS"
  echo "- **Reason for proposal:** $REASON"
  echo "- **Correction count:** $PREV"
  echo "- **Outcome:** $OUTCOME"
  if [[ -n "$T_IN" ]]; then echo "- **Tokens (from closing message):** in $T_IN, out $T_OUT"; fi
  if [[ -n "$METRICS" ]]; then echo "- **Metrics:** $METRICS"; fi
} >> "$LOG"
echo "log-delegation: entry appended to $LOG (correction count $PREV)"

if [[ -n "$T_IN" || -n "$METRICS" ]]; then
  # v3.3.0: a seventh field carries the per-delegation metrics; readers split on " | " and
  # ignore fields they do not know. Rows without tokens still ledger when metrics are given.
  printf '%s | %s | %s | %s | %s | manual: %s%s\n' "$TS" "$AGENT" "$MODEL" "${T_IN:-?}" "${T_OUT:-?}" "${REASON:0:60}" "${METRICS:+ | $METRICS}" >> "$LEDGER"
  echo "log-delegation: ledger row appended (${T_IN:-?} in / ${T_OUT:-?} out, tagged manual${METRICS:+; $METRICS})"
fi
