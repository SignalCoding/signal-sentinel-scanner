#!/usr/bin/env bash
# run-evaluator.sh <TG-ID> <spec-file> [base-ref] [end-ref] [--double] [--skip-preflight]
# WP2 (v1.7.0, revised v1.8.1-cc): runs the fresh-context evaluator as a SEPARATE claude -p
# session at read-only autonomy. The wrapper captures stdout and writes the verdict file itself,
# so the evaluator session needs no write capability at all.
# v1.8.1-cc: model is read from the evaluator agent's frontmatter (single source of truth);
# the claude-CLI existence check is restored; task-group row extraction uses Python (no jq).
# v1.11.4: (a) the evaluator agent definition is existence-checked (a missing file used to
# yield an EMPTY system prompt = unpinned evaluator); (b) the verdict is written to a temp
# file and moved into place only on claude-CLI success, so a mid-run failure can never leave
# a truncated file that looks like a real verdict; (c) --allowedTools now matches the agent
# frontmatter (TodoWrite added); (d) optional --double flag runs the evaluation TWICE and
# reports both verdicts plus whether they agree (judge-consistency doctrine, mechanically:
# agreement on PASS -> exit 0; any NEEDS_WORK or disagreement -> exit 3).
# v3.0.0 (harvest 2026-09, six projects):
#   MODEL  - _docs/ai/models.env (stamped by bootstrap, EVALUATOR_MODEL=...) is the first
#            source; the agent frontmatter is second; the library default is third. A retired
#            model ID made the evaluator fail with nothing on disk for months. The project's
#            .claude/agents/evaluator.md model: line is rewritten to match models.env so the
#            agent route and this wrapper never disagree.
#   FAILED - a CLI failure now leaves a sidecar verdicts/<TG>-verdict.failed-<epoch>.log with
#            the model name, exit code and the CLI's stderr. Silence is not a verdict.
#   SCOPE  - evidence content is limited to the task group's own files (its criteria's
#            evidence + red baseline + <TG>-prefixed files), capped per file and in total,
#            binary/non-UTF-8 files skipped by name. A 34-row project was sending every log
#            it had ever produced on every verdict.
#   RANGE  - optional end-ref (default HEAD) so a verdict can be re-run on a historical range.
#   BODY   - a PASS verdict must carry one line per criterion ID in the task group; a verdict
#            body citing no criterion ID is rejected as NEEDS_WORK (the evaluator answered the
#            wrong question).
#   PRE    - pre-flight before any model call: verify-gate --tg must pass; a *.testresults.txt
#            evidence file holding more than one test-run summary is refused (one run per file).
#            --skip-preflight bypasses it loudly (recorded in the verdict header).
# v3.2.0 (Truer Gates, external architecture review):
#   TOOLS  - read-only is now STRUCTURAL, not a permission preference. --allowedTools only skips
#            prompts; the evaluator session is started with --tools "Read,Grep,Glob" (nothing
#            else exists), --disallowedTools "mcp__*" (no MCP tools), and --restricted when the
#            CLI is 2.1.248 or later (no command tools, file tools confined to the working
#            directory, only managed settings load). TodoWrite is gone. --effort (default high),
#            --max-turns (default 40) and an optional --max-budget-usd bound the run.
#            EVALUATOR_EFFORT / EVALUATOR_MAX_TURNS / EVALUATOR_MAX_BUDGET_USD override.
#   IMAGES - image evidence (*.png, *.jpg, *.pdf) is passed by PATH for the evaluator to open with
#            Read; a screenshot it did not open is unverified evidence, and it says so.
#   BASE   - the default base ref is the task group's recorded baseCommit (written by
#            new-task-group.sh), not HEAD~1; an explicit base-ref argument still wins.
# v3.3.0 (Truer Gates II):
#   JSON   - the verdict is STRUCTURED: `--output-format json --json-schema` against
#            _docs/ai/verify/verdict.schema.json; the CLI validates it, this script renders
#            verdicts/<TG>-verdict.md from it (the VERDICT line and one line per criterion are
#            still there for readers and older tooling) and keeps verdicts/<TG>-verdict.json.
#            A run whose result is not a validated object is a FAILED run with a sidecar, never a
#            misparsed PASS. The resolved model ID (modelUsage) goes in the header.
#   VERIFY - --verify-findings (default for a task group whose risk is "high"; --no-verify-findings
#            turns it off) runs a second restricted session that opens each BLOCKING finding and
#            marks it CONFIRMED or UNCONFIRMED with the line it saw. The verdict is NEEDS_WORK only
#            on CONFIRMED blocking findings; unconfirmed ones stay in the file as advisories.
#   HISTORY- every run appends one line to verdicts/<TG>-verdict.history.log (date, verdict,
#            model, counts); the metrics report reads cycles and first-pass success from it.
set -euo pipefail

DOUBLE=0; SKIP_PREFLIGHT=0; VERIFY_FINDINGS=""
POSITIONAL=()
for _arg in "$@"; do
  case "$_arg" in
    --double) DOUBLE=1 ;;
    --skip-preflight) SKIP_PREFLIGHT=1 ;;
    --verify-findings) VERIFY_FINDINGS=1 ;;
    --no-verify-findings) VERIFY_FINDINGS=0 ;;
    *) POSITIONAL+=("$_arg") ;;
  esac
done

USAGE="Usage: run-evaluator.sh <TG-ID> <spec-file> [base-ref] [end-ref] [--double] [--skip-preflight] [--verify-findings|--no-verify-findings]"
TG_ID="${POSITIONAL[0]:?$USAGE}"
SPEC_FILE="${POSITIONAL[1]:?$USAGE}"
BASE_REF="${POSITIONAL[2]:-HEAD~1}"
BASE_REF_EXPLICIT="${POSITIONAL[2]:-}"
END_REF="${POSITIONAL[3]:-HEAD}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY_DIR="$PROJECT_ROOT/_docs/ai/verify"
VERDICT_FILE="$VERIFY_DIR/verdicts/${TG_ID}-verdict.md"
SCHEMA_FILE="$VERIFY_DIR/verdict.schema.json"
HISTORY_FILE="$VERIFY_DIR/verdicts/${TG_ID}-verdict.history.log"
RESULTS="$VERIFY_DIR/verify-results.json"
MODELS_ENV="$PROJECT_ROOT/_docs/ai/models.env"
LIBRARY_DEFAULT_EVALUATOR_MODEL="claude-opus-5-5"

# --- CONFIG ---
# Read-only enforcement is STRUCTURAL (v3.2.0): --tools names the only tools that exist,
# --disallowedTools removes MCP tools, --restricted (CLI 2.1.248+) removes command tools and
# confines file tools to the working directory. --allowedTools is kept only so the three tools
# never prompt. We pass the evaluator system prompt from .claude/agents/evaluator.md explicitly
# so behaviour is pinned. Fresh context is guaranteed by this being a separate claude -p process.
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
EVALUATOR_EFFORT="${EVALUATOR_EFFORT:-high}"
EVALUATOR_MAX_TURNS="${EVALUATOR_MAX_TURNS:-40}"
EVALUATOR_MAX_BUDGET_USD="${EVALUATOR_MAX_BUDGET_USD:-}"
RESTRICTED_FLOOR="2.1.248"
EVALUATOR_DEF="$PROJECT_ROOT/.claude/agents/evaluator.md"
# v1.11.4 (a): a missing agent definition used to sail through sed and produce an EMPTY
# system prompt - an UNPINNED evaluator. Hard-fail with a clear error instead.
if [[ ! -f "$EVALUATOR_DEF" ]]; then
  echo "ERROR: evaluator agent definition not found: $EVALUATOR_DEF" >&2
  echo "Without it the evaluator system prompt cannot be pinned (the session would run unpinned)." >&2
  echo "Restore .claude/agents/evaluator.md (delivered by bootstrap from the template) and re-run." >&2
  exit 1
fi

if [[ ! -f "$SCHEMA_FILE" ]]; then
  echo "ERROR: verdict schema not found: $SCHEMA_FILE (delivered by bootstrap --refresh-hooks)." >&2; exit 1
fi

# v3.0.0: model resolution - models.env first, agent frontmatter second, library default third.
FRONTMATTER_MODEL="$(sed -n 's/^model:[[:space:]]*//p' "$EVALUATOR_DEF" 2>/dev/null | head -1 | tr -d '[:space:]')"
ENV_MODEL=""
if [[ -f "$MODELS_ENV" ]]; then
  ENV_MODEL="$(sed -n 's/^EVALUATOR_MODEL=[[:space:]]*//p' "$MODELS_ENV" 2>/dev/null | head -1 | tr -d '"'"'"'[:space:]')"
fi
if [[ -n "$ENV_MODEL" ]]; then
  EVAL_MODEL="$ENV_MODEL"; MODEL_SOURCE="_docs/ai/models.env"
  if [[ "$FRONTMATTER_MODEL" != "$ENV_MODEL" ]]; then
    # Keep the agent route (Claude Code's own Task tool reads the frontmatter) in lockstep.
    if sed -i.bak "s|^model:.*|model: $ENV_MODEL|" "$EVALUATOR_DEF" 2>/dev/null; then
      rm -f "$EVALUATOR_DEF.bak"
      echo "run-evaluator: NOTE - .claude/agents/evaluator.md model: updated to $ENV_MODEL from models.env (was '${FRONTMATTER_MODEL:-unset}')." >&2
    fi
  fi
elif [[ -n "$FRONTMATTER_MODEL" ]]; then
  EVAL_MODEL="$FRONTMATTER_MODEL"; MODEL_SOURCE=".claude/agents/evaluator.md"
  echo "run-evaluator: NOTE - _docs/ai/models.env absent or has no EVALUATOR_MODEL; using the agent frontmatter ($EVAL_MODEL). Stamp it: scripts/bootstrap.sh --refresh-hooks, or write EVALUATOR_MODEL=<id> to _docs/ai/models.env." >&2
else
  EVAL_MODEL="$LIBRARY_DEFAULT_EVALUATOR_MODEL"; MODEL_SOURCE="library default"
  echo "run-evaluator: WARNING - no evaluator model pinned anywhere; using the library default ($EVAL_MODEL)." >&2
fi
command -v "$CLAUDE_BIN" >/dev/null 2>&1 || { echo "claude CLI not found on PATH" >&2; exit 1; }
[[ -f "$SPEC_FILE" ]] || { echo "Spec file not found: $SPEC_FILE" >&2; exit 1; }
[[ -f "$RESULTS" ]] || { echo "verify-results.json not found" >&2; exit 1; }

# v3.2.0: version floor for --restricted. `claude --version` prints e.g. "2.1.270 (Claude Code)".
# Below the floor the structural set (--tools / --disallowedTools) still applies; only the
# sandboxing flag is omitted, and the verdict header says so.
CC_VERSION="$("$CLAUDE_BIN" --version </dev/null 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
version_ge() {  # version_ge <a> <b>: 0 when a >= b (dotted numeric)
  local IFS=. a b i; read -r -a a <<<"$1"; read -r -a b <<<"$2"
  for i in 0 1 2; do
    local x="${a[$i]:-0}" y="${b[$i]:-0}"
    (( 10#$x > 10#$y )) && return 0
    (( 10#$x < 10#$y )) && return 1
  done
  return 0
}
CLAUDE_ARGS=(-p --model "$EVAL_MODEL" --tools "Read,Grep,Glob" --allowedTools "Read,Grep,Glob" --disallowedTools "mcp__*" --effort "$EVALUATOR_EFFORT" --max-turns "$EVALUATOR_MAX_TURNS" --output-format json)
[[ -n "$EVALUATOR_MAX_BUDGET_USD" ]] && CLAUDE_ARGS+=(--max-budget-usd "$EVALUATOR_MAX_BUDGET_USD")
if [[ -n "$CC_VERSION" ]] && version_ge "$CC_VERSION" "$RESTRICTED_FLOOR"; then
  CLAUDE_ARGS+=(--restricted)
  SANDBOX_NOTE="restricted read-only (claude ${CC_VERSION}: --restricted, tools Read/Grep/Glob only, no MCP, no shell)"
else
  SANDBOX_NOTE="read-only by tool set (claude ${CC_VERSION:-unknown} is below ${RESTRICTED_FLOOR}: --restricted unavailable; tools Read/Grep/Glob only, no MCP)"
  echo "run-evaluator: NOTE - $SANDBOX_NOTE. Update the CLI (claude update) for the sandboxed evaluator." >&2
fi
# ---------------------------------------------------------------------------

PY=""; PY_ARGS=()
# Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  # Reject non-functional interpreters (e.g. the Windows Store python3 alias stub)
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
[[ -z "$PY" ]] && { echo "run-evaluator: Python 3 is required (python3/python/py not found)." >&2; exit 1; }

# Task-group rows + the evidence files THIS group owns (v3.0.0 scoping) + its baseCommit (v3.2.0).
TG_JSON="$(RESULTS_PATH="$RESULTS" TG_ID_VAL="$TG_ID" pyc -c '
import json, os, sys
data = json.load(open(os.environ["RESULTS_PATH"], encoding="utf-8"))
rows = [tg for tg in data.get("taskGroups", []) if tg.get("id") == os.environ["TG_ID_VAL"]]
files = []
for tg in rows:
    rb = tg.get("redBaseline")
    if isinstance(rb, str) and rb.strip(): files.append(rb.strip())
    for c in tg.get("criteria", []):
        files.extend(c.get("evidence") or [])
ids = [c.get("id","") for tg in rows for c in tg.get("criteria", [])]
base = (rows[0].get("baseCommit") or "") if rows else ""
print(json.dumps({"rows": rows, "files": sorted(set(files)), "ids": ids, "base": base}))
')"
TG_ROWS="$(printf '%s' "$TG_JSON" | pyc -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["rows"], indent=2))')"
TG_FILES="$(printf '%s' "$TG_JSON" | pyc -c 'import json,sys; print("\n".join(json.load(sys.stdin)["files"]))')"
TG_CRITERIA_IDS="$(printf '%s' "$TG_JSON" | pyc -c 'import json,sys; print(" ".join(i for i in json.load(sys.stdin)["ids"] if i))')"
TG_BASE_COMMIT="$(printf '%s' "$TG_JSON" | pyc -c 'import json,sys; print(json.load(sys.stdin)["base"].strip())')"
TG_RISK="$(printf '%s' "$TG_JSON" | pyc -c 'import json,sys; r=json.load(sys.stdin)["rows"]; print((r[0].get("risk") or "medium") if r else "medium")')"
if [[ -z "$VERIFY_FINDINGS" ]]; then
  if [[ "$TG_RISK" == "high" ]]; then VERIFY_FINDINGS=1; else VERIFY_FINDINGS=0; fi
fi
if [[ "$TG_ROWS" == "[]" ]]; then
  echo "ERROR: task group '$TG_ID' not found in verify-results.json" >&2; exit 1
fi

# v3.2.0: the diff the evaluator judges starts where the task group started. new-task-group.sh
# records baseCommit; when present it is the default base (an explicit argument still wins).
# A recorded baseCommit that no longer resolves is an error, not a silent fallback: the
# evaluator would otherwise judge the last commit alone and miss everything before it.
# v1.11.3 (L-07): with no baseCommit, the legacy default HEAD~1 applies, falling back to the
# empty tree on a single-commit repo; an explicitly passed ref that does not resolve errors.
EMPTY_TREE="$(git -C "$PROJECT_ROOT" hash-object -t tree /dev/null)"
BASE_SOURCE="argument"
if [[ "$BASE_REF_EXPLICIT" == "" ]]; then
  if [[ -n "$TG_BASE_COMMIT" ]]; then
    if git -C "$PROJECT_ROOT" rev-parse --verify --quiet "$TG_BASE_COMMIT^{commit}" >/dev/null; then
      BASE_REF="$TG_BASE_COMMIT"; BASE_SOURCE="baseCommit"
    else
      echo "ERROR: $TG_ID records baseCommit '$TG_BASE_COMMIT' and it does not resolve in this repository (rewritten history, shallow clone, or a different repo). Pass the base ref explicitly: run-evaluator.sh $TG_ID <spec> <base-ref>." >&2
      exit 1
    fi
  else
    BASE_SOURCE="HEAD~1 (no baseCommit recorded for $TG_ID; groups opened before v3.2.0)"
    echo "run-evaluator: NOTE - $TG_ID has no baseCommit; diffing from HEAD~1. Pass the base ref explicitly for a multi-commit group." >&2
  fi
fi
if ! git -C "$PROJECT_ROOT" rev-parse --verify --quiet "$BASE_REF^{commit}" >/dev/null; then
  if [[ "$BASE_REF_EXPLICIT" == "" ]]; then
    echo "run-evaluator: NOTE - default base HEAD~1 does not resolve (single-commit repo); diffing against the empty tree." >&2
    BASE_REF="$EMPTY_TREE"
  else
    echo "ERROR: base ref '$BASE_REF' does not resolve in this repository. Pass a valid ref (or omit it; on a single-commit repo the script diffs against the empty tree)." >&2
    exit 1
  fi
fi
if ! git -C "$PROJECT_ROOT" rev-parse --verify --quiet "$END_REF^{commit}" >/dev/null; then
  echo "ERROR: end ref '$END_REF' does not resolve in this repository." >&2; exit 1
fi
DIFF="$(git -C "$PROJECT_ROOT" diff "$BASE_REF"..."$END_REF" 2>/dev/null || git -C "$PROJECT_ROOT" diff "$BASE_REF" "$END_REF")"

# ------------------------------------------------------------------
# v3.0.0 pre-flight: do not spend a model call on evidence the gate would refuse.
# ------------------------------------------------------------------
PREFLIGHT_NOTE="pre-flight: verify-gate --tg PASS; single-run evidence check PASS"
if [[ "$SKIP_PREFLIGHT" == "0" ]]; then
  if ! bash "$PROJECT_ROOT/scripts/verify-gate.sh" --tg "$TG_ID" >/dev/null 2>"$VERIFY_DIR/.preflight.err"; then
    echo "ERROR: verify-gate.sh --tg $TG_ID FAILED - the evaluator is not run on an ungated task group:" >&2
    cat "$VERIFY_DIR/.preflight.err" >&2; rm -f "$VERIFY_DIR/.preflight.err"; exit 1
  fi
  rm -f "$VERIFY_DIR/.preflight.err"
  MULTI="$(EVDIR="$VERIFY_DIR/evidence" FILES="$TG_FILES" pyc - <<'PYEOF'
import os, re
evdir = os.environ["EVDIR"]
# One summary line per framework; a second occurrence means two runs were appended into one file.
SUMMARY = re.compile(r"^(Passed!|Failed!|Total tests:|Test Files\s+\d|Tests:\s+\d|Ran \d+ tests?|=+ \d+ (passed|failed)|\d+ passing|\d+ tests? (passed|failed|completed)|(PASS|FAIL): )", re.M)
bad = []
for name in os.environ.get("FILES", "").split("\n"):
    name = name.strip()
    if not name.endswith(".testresults.txt"): continue
    p = os.path.join(evdir, name)
    if not os.path.isfile(p): continue
    try:
        text = open(p, encoding="utf-8", errors="strict").read()
    except (UnicodeDecodeError, OSError):
        continue
    n = len(SUMMARY.findall(text))
    if n > 1: bad.append(f"{name} ({n} test-run summaries)")
print("\n".join(bad))
PYEOF
)"
  if [[ -n "$MULTI" ]]; then
    echo "ERROR: evidence file(s) contain more than one test-run summary - one run per file (single-run log rule):" >&2
    printf '%s\n' "$MULTI" | sed 's/^/  /' >&2
    echo "Re-run the suite into a fresh file (> not >>), reference that file, and re-run the evaluator. (--skip-preflight overrides, recorded in the verdict header.)" >&2
    exit 1
  fi
else
  PREFLIGHT_NOTE="pre-flight: SKIPPED by --skip-preflight (the gate and single-run checks were NOT applied before this verdict)"
  echo "run-evaluator: WARNING - $PREFLIGHT_NOTE" >&2
fi

EVIDENCE_LIST="$(cd "$VERIFY_DIR/evidence" 2>/dev/null && ls -la -- $(printf '%s\n' "$TG_FILES"; ls | grep -E "^${TG_ID}[.-]" 2>/dev/null) 2>/dev/null | sort -u || echo "none")"
# v3.0.0: scoped evidence text - this group's files only, per-file and total caps, binaries skipped.
EVIDENCE_TEXT="$(EVDIR="$VERIFY_DIR/evidence" EVDIR_REL="_docs/ai/verify/evidence" FILES="$TG_FILES" TG="$TG_ID" pyc - <<'PYEOF'
import os
evdir = os.environ["EVDIR"]; tg = os.environ["TG"]
PER_FILE = 12000; TOTAL = 160000
names = [n.strip() for n in os.environ.get("FILES", "").split("\n") if n.strip()]
if os.path.isdir(evdir):
    for n in sorted(os.listdir(evdir)):
        if (n.startswith(tg + ".") or n.startswith(tg + "-")) and n not in names:
            names.append(n)
out = []; used = 0; skipped = []; images = []
for n in names:
    p = os.path.join(evdir, n)
    if not os.path.isfile(p): continue
    if n.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf")):
        # v3.2.0: images are passed by path; the Read tool opens them. Not inlined here.
        images.append(os.environ.get("EVDIR_REL", evdir).replace("\\", "/") + "/" + n); continue
    try:
        raw = open(p, "rb").read(PER_FILE + 1)
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        skipped.append(f"{n} (not UTF-8 text - skipped)"); continue
    except OSError:
        continue
    truncated = len(raw) > PER_FILE
    text = text[:PER_FILE]
    if used + len(text) > TOTAL:
        skipped.append(f"{n} (total evidence cap reached - not included)"); continue
    used += len(text)
    out.append(f"----- {n}{' [TRUNCATED to first %d bytes]' % PER_FILE if truncated else ''} -----\n{text}\n")
if images:
    out.append("----- IMAGE EVIDENCE (open each with Read; state what it shows; an image you did not open is unverified) -----\n" + "\n".join(images) + "\n")
if skipped:
    out.append("----- NOT INCLUDED -----\n" + "\n".join(skipped) + "\n")
print("".join(out) if out else "(no text evidence for this task group)")
PYEOF
)"

PROMPT=$(cat <<PROMPTEOF
Evaluate task group ${TG_ID}. Criterion IDs in scope: ${TG_CRITERIA_IDS:-none}.

=== SPEC (relevant section incl. EARS criteria and Non-goals) ===
$(cat "$SPEC_FILE")

=== GIT DIFF (${BASE_REF}...${END_REF}) ===
${DIFF}

=== VERIFY-RESULTS ROWS ===
${TG_ROWS}

=== EVIDENCE FILES (this task group) ===
${EVIDENCE_LIST}

=== EVIDENCE CONTENT (this task group's text files, capped) ===
${EVIDENCE_TEXT}
PROMPTEOF
)

mkdir -p "$VERIFY_DIR/verdicts"
SYS="$(awk 'f;/^---$/{c++;if(c==2)f=1}' "$EVALUATOR_DEF")"   # body after frontmatter

# v3.3.0: one evaluator run = one structured object. The CLI validates the object against the
# schema; the script renders the markdown verdict from it and keeps the JSON beside it. A run
# whose result is not a validated object leaves a SIDECAR (v3.0.0) and no verdict file.
SCHEMA_JSON="$(cat "$SCHEMA_FILE")"
VERIFIER_SYS='You are a FINDING VERIFIER with fresh context and read-only tools. You receive findings another reviewer raised against this repository. For EACH finding: open the file at the line (or search for the claim), decide whether the claim is true of the code AS IT IS. CONFIRMED means you saw it and quote the line that shows it in verifier_note. UNCONFIRMED means you could not reproduce it, it is mitigated elsewhere (name where), or it is not a defect against the criterion. Never add findings, never soften a confirmed one, never confirm from the reviewer description alone. Return every finding, unchanged except confirmation and verifier_note.'
VERIFIER_SCHEMA='{"type":"object","required":["findings"],"additionalProperties":false,"properties":{"findings":{"type":"array","items":{"type":"object","required":["severity","criterion","file","claim","confirmation","verifier_note"],"additionalProperties":false,"properties":{"severity":{"type":"string","enum":["BLOCKING","ADVISORY"]},"criterion":{"type":"string"},"file":{"type":"string"},"line":{"type":"integer"},"claim":{"type":"string"},"evidence":{"type":"string"},"confirmation":{"type":"string","enum":["CONFIRMED","UNCONFIRMED"]},"verifier_note":{"type":"string","maxLength":300}}}}}}'

# claude_json <label> <system-prompt> <schema> <prompt-text> -> prints the CLI's JSON result on stdout, 1 on failure
claude_json() {
  local label="$1" sys="$2" schema="$3" prompt="$4" out err rc
  out="$(mktemp "$VERIFY_DIR/verdicts/.${TG_ID}-${label}.XXXXXX")"; err="$out.err"
  # Prompt via stdin: spec + diff + evidence routinely exceed the Windows argv size limit
  if printf '%s' "$prompt" | "$CLAUDE_BIN" "${CLAUDE_ARGS[@]}" --json-schema "$schema" --append-system-prompt "$sys" >"$out" 2>"$err"; then
    cat "$out"; rm -f "$out" "$err"; return 0
  else
    rc=$?
    local sidecar="$VERIFY_DIR/verdicts/${TG_ID}-verdict.failed-$(date +%s).log"
    {
      echo "# Evaluator run FAILED for ${TG_ID} (${label})"
      echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "model: ${EVAL_MODEL} (from ${MODEL_SOURCE})"
      echo "exit: $rc"
      echo "command: $CLAUDE_BIN ${CLAUDE_ARGS[*]} --json-schema <schema> --append-system-prompt <${label} system prompt>"
      echo ""; echo "--- claude CLI stderr ---"; cat "$err" 2>/dev/null || true
      echo ""; echo "--- stdout (discarded as a verdict) ---"; tail -c 4000 "$out" 2>/dev/null || true
    } > "$sidecar"
    rm -f "$out" "$err"
    echo "ERROR: claude CLI failed (exit $rc) with model '$EVAL_MODEL' (from $MODEL_SOURCE); NO verdict was written." >&2
    echo "       Details: $sidecar" >&2
    echo "       If the error names an unknown or retired model, update EVALUATOR_MODEL in _docs/ai/models.env (Model-Release Ritual in the library's UPDATE-PROCEDURE)." >&2
    return 1
  fi
}

# render_verdict <result-json> <label> <verify-json-or-empty> <md-out> <json-out>
# Validates the result object (subtype success + structured_output), merges verifier confirmations,
# computes the final verdict, writes the markdown and JSON files, appends the history line.
# Exit: 0 PASS, 3 NEEDS_WORK, 1 invalid result.
render_verdict() {
  RESULT_JSON="$1" LABEL="$2" VERIFY_JSON="$3" MD_OUT="$4" JSON_OUT="$5" \
  TG="$TG_ID" IDS="$TG_CRITERIA_IDS" BASE="$BASE_REF" END="$END_REF" BASE_SRC="$BASE_SOURCE" \
  MODEL="$EVAL_MODEL" MODEL_SRC="$MODEL_SOURCE" SANDBOX="$SANDBOX_NOTE" EFFORT="$EVALUATOR_EFFORT" TURNS="$EVALUATOR_MAX_TURNS" \
  BUDGET="$EVALUATOR_MAX_BUDGET_USD" PREFLIGHT="$PREFLIGHT_NOTE" HISTORY="$HISTORY_FILE" RISK="$TG_RISK" VERIFIED="$VERIFY_FINDINGS" \
  "$PY" "${PY_ARGS[@]}" - <<'PYEOF'
import json, os, sys, datetime
def fail(msg):
    print("ERROR: " + msg, file=sys.stderr); sys.exit(1)
try:
    res = json.loads(os.environ["RESULT_JSON"])
except json.JSONDecodeError as exc:
    fail(f"evaluator output is not a JSON result object ({exc}); a text verdict is not accepted - the CLI must support --output-format json --json-schema")
if res.get("subtype") not in (None, "success") or res.get("is_error"):
    fail(f"evaluator result subtype '{res.get('subtype')}' is_error={res.get('is_error')}: {str(res.get('result'))[:300]}")
v = res.get("structured_output")
if not isinstance(v, dict) or "verdict" not in v:
    fail("evaluator result carries no validated structured_output (schema not satisfied, or run ended without one)")
# resolved model
mu = res.get("modelUsage") or {}
resolved = ", ".join(sorted(mu.keys())) if isinstance(mu, dict) and mu else (res.get("model") or "unresolved")
usage = res.get("usage") or {}
tin = usage.get("input_tokens", "?"); tout = usage.get("output_tokens", "?")
cost = res.get("total_cost_usd", "?"); turns = res.get("num_turns", "?")
# merge verifier confirmations
verify_raw = os.environ.get("VERIFY_JSON") or ""
verified = False
if verify_raw.strip():
    try:
        vres = json.loads(verify_raw); vo = vres.get("structured_output") or {}
        conf = vo.get("findings") or []
        for f in v.get("findings", []):
            for c in conf:
                if c.get("file") == f.get("file") and c.get("claim") == f.get("claim"):
                    f["confirmation"] = c.get("confirmation", "UNCHECKED"); f["verifier_note"] = c.get("verifier_note", "")
        verified = True
    except (json.JSONDecodeError, AttributeError):
        print("run-evaluator: NOTE - finding verification output unreadable; findings stay UNCHECKED", file=sys.stderr)
ids = [i for i in os.environ.get("IDS", "").split() if i]
crit_status = {c.get("id"): c for c in v.get("criteria", []) if isinstance(c, dict)}
missing = [i for i in ids if i not in crit_status]
blocking = [f for f in v.get("findings", []) if f.get("severity") == "BLOCKING"]
for f in v.get("findings", []):
    f.setdefault("confirmation", "UNCHECKED")
confirmed = [f for f in blocking if f.get("confirmation") == "CONFIRMED"]
unconfirmed = [f for f in blocking if f.get("confirmation") == "UNCONFIRMED"]
unchecked = [f for f in blocking if f.get("confirmation") == "UNCHECKED"]
# final verdict: the evaluator's call, overridden only by verification outcomes and missing coverage
final = v.get("verdict", "NEEDS_WORK")
reasons = []
if verified and final == "NEEDS_WORK" and blocking and not confirmed and not unchecked \
   and all(crit_status.get(i, {}).get("status") in ("PASS", "BLOCKED_OK") or any(f.get("criterion") == i for f in unconfirmed) for i in ids):
    final = "PASS"; reasons.append("every blocking finding UNCONFIRMED by the verifier")
    for i in ids:
        c = crit_status.get(i)
        if c and c.get("status") == "NEEDS_WORK":
            c["status"] = "PASS"; c["note"] = ((c.get("note") or "") + " [finding unconfirmed by verifier]").strip()
if final == "PASS" and confirmed:
    final = "NEEDS_WORK"; reasons.append("blocking finding CONFIRMED")
if final == "PASS" and any(crit_status.get(i, {}).get("status") in ("NEEDS_WORK", "UNVERIFIED") for i in ids):
    final = "NEEDS_WORK"; reasons.append("a criterion is NEEDS_WORK or UNVERIFIED")
if missing:
    final = "NEEDS_WORK"; reasons.append("verdict does not judge every criterion in scope: " + ", ".join(missing))
v["verdict"] = final
v["resolvedModel"] = resolved
v["taskGroup"] = os.environ["TG"]
v["judgedAt"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
v["verification"] = "verified" if verified else "unchecked"
v["usage"] = {"input": tin, "output": tout, "turns": turns, "costUsd": cost}
with open(os.environ["JSON_OUT"], "w", encoding="utf-8") as fh:
    json.dump(v, fh, indent=2); fh.write("\n")
lines = []
lines.append(f"# Verdict: {os.environ['TG']}{os.environ['LABEL']}")
lines.append(f"date: {v['judgedAt']}")
lines.append(f"range: {os.environ['BASE']}...{os.environ['END']} (base from {os.environ['BASE_SRC']})")
lines.append(f"evaluator: claude -p ({os.environ['MODEL']} from {os.environ['MODEL_SRC']}; resolved: {resolved}), {os.environ['SANDBOX']}, effort {os.environ['EFFORT']}, max-turns {os.environ['TURNS']}" + (f", max-budget-usd {os.environ['BUDGET']}" if os.environ.get('BUDGET') else "") + ", agents/evaluator.md system prompt, structured output (verdict.schema.json)")
lines.append(f"risk: {os.environ['RISK']}; finding verification: {'run' if verified else 'not run'}; usage: {tin} in / {tout} out, {turns} turns, cost {cost}")
lines.append(os.environ["PREFLIGHT"])
lines.append("")
lines.append(f"VERDICT: {final}")
if reasons: lines.append("verdict basis: " + "; ".join(reasons))
if v.get("summary"): lines.append(""); lines.append(v["summary"])
lines.append(""); lines.append("## Criteria")
for i in ids:
    c = crit_status.get(i)
    if c: lines.append(f"- {i}: {c.get('status')}" + (f" - {c.get('note')}" if c.get("note") else ""))
    else: lines.append(f"- {i}: NOT JUDGED")
for cid, c in crit_status.items():
    if cid not in ids: lines.append(f"- {cid}: {c.get('status')} (not in scope)")
lines.append(""); lines.append("## Findings")
if not v.get("findings"): lines.append("- none")
for f in v.get("findings", []):
    loc = f.get("file", "?") + (f":{f['line']}" if f.get("line") is not None else "")
    lines.append(f"- [{f.get('severity')}][{f.get('confirmation')}] {f.get('criterion','-')} {loc}: {f.get('claim','')}" + (f" (evidence: {f['evidence']})" if f.get("evidence") else "") + (f" (verifier: {f['verifier_note']})" if f.get("verifier_note") else ""))
if v.get("images_opened"): lines.append(""); lines.append("images opened: " + ", ".join(v["images_opened"]))
if v.get("evidence_not_opened"): lines.append("evidence not opened: " + ", ".join(v["evidence_not_opened"]))
with open(os.environ["MD_OUT"], "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
with open(os.environ["HISTORY"], "a", encoding="utf-8") as fh:
    fh.write(f"{v['judgedAt']} | {final} | {resolved} | blocking={len(blocking)} confirmed={len(confirmed)} unconfirmed={len(unconfirmed)} unchecked={len(unchecked)} advisory={len(v.get('findings', [])) - len(blocking)} | in={tin} out={tout} turns={turns}{os.environ['LABEL']}\n")
print(f"Verdict written: {os.environ['MD_OUT']} ({final}; {len(confirmed)} confirmed, {len(unconfirmed)} unconfirmed, {len(unchecked)} unchecked blocking finding(s))")
sys.exit(0 if final == "PASS" else 3)
PYEOF
}

# run_eval <md-out> <label> -> 0 PASS, 3 NEEDS_WORK, 1 failed run
run_eval() {
  local out="$1" label="$2" json_out="${1%.md}.json" result verify="" rc
  mkdir -p "$VERIFY_DIR/verdicts"
  result="$(claude_json "eval" "$SYS" "$SCHEMA_JSON" "$PROMPT")" || return 1
  if [[ "$VERIFY_FINDINGS" == "1" ]]; then
    local blocking
    blocking="$(printf '%s' "$result" | pyc -c 'import json,sys
try:
    v=json.load(sys.stdin).get("structured_output") or {}
    print(json.dumps([f for f in v.get("findings",[]) if f.get("severity")=="BLOCKING"]))
except Exception: print("[]")' | tr -d '\r')"
    if [[ "$blocking" != "[]" ]]; then
      local vprompt
      vprompt="$(printf 'Verify these findings against task group %s (criteria in scope: %s). Open every file named; decide CONFIRMED or UNCONFIRMED per finding and say what you saw.\n\n=== FINDINGS ===\n%s\n\n=== SPEC SECTION ===\n%s\n' "$TG_ID" "${TG_CRITERIA_IDS:-none}" "$blocking" "$(cat "$SPEC_FILE")")"
      verify="$(claude_json "verify" "$VERIFIER_SYS" "$VERIFIER_SCHEMA" "$vprompt")" || { echo "run-evaluator: NOTE - finding verification failed; findings stay UNCHECKED" >&2; verify=""; }
    fi
  fi
  render_verdict "$result" "$label" "$verify" "$out" "$json_out"; rc=$?
  # verdict length cap (~2,000 tokens): noted, not refused
  local _vb; _vb="$(wc -c < "$out" | tr -d '[:space:]')"
  [[ "$_vb" -gt 8000 ]] && echo "NOTE: verdict is ${_vb} bytes (cap ~8,000 / 2,000 tokens) - findings are file:line, never pasted logs" >&2
  return "$rc"
}

# Extract the VERDICT token from a rendered verdict file; empty if absent.
verdict_of() {
  sed -n 's/^VERDICT:[[:space:]]*//p' "$1" 2>/dev/null | tr -d '\r' | awk 'NR==1{print $1}'
}

if [[ "$DOUBLE" == "1" ]]; then
  # v1.11.4 (d): judge-consistency doctrine, mechanically - run the evaluation twice in two
  # fresh claude -p sessions, report both verdicts and whether they agree.
  VERDICT_FILE2="${VERDICT_FILE%.md}-run2.md"
  set +e
  run_eval "$VERDICT_FILE" " (double run 1 of 2)"; RC1=$?
  run_eval "$VERDICT_FILE2" " (double run 2 of 2)"; RC2=$?
  set -e
  [[ "$RC1" == "1" || "$RC2" == "1" ]] && exit 1
  R1="$(verdict_of "$VERDICT_FILE" || true)"; R2="$(verdict_of "$VERDICT_FILE2" || true)"
  echo ""
  echo "Run 1 verdict: ${R1:-<none>}  ($VERDICT_FILE)"
  echo "Run 2 verdict: ${R2:-<none>}  ($VERDICT_FILE2)"
  if [[ "$R1" == "$R2" ]]; then
    echo "Consistency: AGREE ($R1)"
    if [[ "$R1" == "PASS" ]]; then exit 0; else exit 3; fi
  else
    echo "Consistency: DISAGREE ($R1 vs $R2) - the evaluation is unstable on this task group;"
    echo "treat as NEEDS_WORK and investigate before accepting either verdict."
    exit 3
  fi
fi

set +e
run_eval "$VERDICT_FILE" ""; RC=$?
set -e
exit "$RC"
