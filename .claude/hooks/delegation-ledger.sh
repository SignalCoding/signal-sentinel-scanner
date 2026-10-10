#!/usr/bin/env bash
# delegation-ledger.sh - PostToolUse hook (v1.11.0, Rec 3 / B4)
# Machine-captured half of the delegation audit trail: one line per sub-agent delegation,
# written by the shell, not the model - complete by construction in confirm AND auto mode.
# Matched on the Agent tool (sub-agent spawn; "Task" before CLI 2.1.63, kept as an alias). Appends:
#   timestamp | agent-type | model | tokens_in | tokens_out | prompt:<chars> sha256:<12 hex>
# to _docs/ai/logs/delegation-ledger.log. Never blocks (informational; exit 0 always).
# v3.2.0: the prompt TEXT is no longer stored - this log is committed, and a brief can carry a
# secret, a customer name or a path. Length and hash keep the row matchable to the reasoned
# *_delegation.md entry (delegation-routing Step 7) without the log holding the words.
# v2.4.0 (spend work order T1): token fields convert waste from an event count into a COST.
# The hook probes the documented candidate payload paths for usage figures; when absent it
# records "?" and prints a loud NOTE - a missing count is a visible gap, never a silent zero.
# Field names remain unverified against a live delegation payload until first real use (the
# same disclosure class as v1.11.0's original payload-field note).
# Degraded policy: no Python -> loud skip (see hooks README, Degraded-environment policy).
set -uo pipefail
P="${CLAUDE_PROJECT_DIR:-$(pwd)}"
LOG_DIR="$P/_docs/ai/logs"
LEDGER="$LOG_DIR/delegation-ledger.log"

PY=""; PY_ARGS=()
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
if [[ -z "$PY" ]]; then
  echo "delegation-ledger: Python 3 missing - this delegation was NOT ledgered (audit gap)." >&2
  exit 0
fi

mkdir -p "$LOG_DIR" 2>/dev/null || exit 0
PAYLOAD="$(cat)"   # capture the hook payload BEFORE any heredoc claims stdin
export PAYLOAD
"$PY" "${PY_ARGS[@]}" - "$LEDGER" <<'PYEOF'
import json, sys, os, datetime
try:
    d = json.loads(os.environ.get("PAYLOAD", "{}"))
    ti = d.get("tool_input", {}) or {}
    agent = ti.get("subagent_type") or ti.get("agent") or "unknown-agent"
    model = ti.get("model") or "inherit"
    import hashlib
    _p = (ti.get("prompt") or "")
    prompt = f"prompt:{len(_p)} sha256:{hashlib.sha256(_p.encode('utf-8','replace')).hexdigest()[:12]}"
    # v2.4.0 T1: probe candidate usage paths (tool_response and top-level, snake and camel)
    tr = d.get("tool_response", {}) or {}
    usage = {}
    for cand in (tr.get("usage"), d.get("usage"), tr.get("tokenUsage"), d.get("tokenUsage")):
        if isinstance(cand, dict):
            usage = cand
            break
    def tok(*keys):
        for k in keys:
            v = usage.get(k)
            if isinstance(v, (int, float)):
                return str(int(v))
        return "?"
    t_in = tok("input_tokens", "inputTokens", "prompt_tokens", "promptTokens")
    t_out = tok("output_tokens", "outputTokens", "completion_tokens", "completionTokens")
    if t_in == "?" or t_out == "?":
        print("delegation-ledger NOTE: token counts absent from payload - spend fields "
              "recorded as '?' (cost accounting incomplete for this delegation).",
              file=sys.stderr)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(sys.argv[1], "a", encoding="utf-8") as fh:
        fh.write(f"{ts} | {agent} | {model} | {t_in} | {t_out} | {prompt}\n")
except Exception as exc:
    print(f"delegation-ledger: write failed ({exc}) - delegation NOT ledgered.", file=sys.stderr)
PYEOF
exit 0
