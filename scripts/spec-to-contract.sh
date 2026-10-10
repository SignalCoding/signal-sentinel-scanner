#!/usr/bin/env bash
# spec-to-contract.sh <phase-spec.md> [--apply] [--tg TG-nn] [--no-gates "<reason>"]
#
# Reads the task groups and criteria of a phase spec (the machine-read syntax in the phase-spec
# template) and opens them in the completion contract FAIL-first - the register's evidence class
# and register rows on every criterion row, gated halves BLOCKED with their open item - through
# the sanctioned helpers (new-task-group.sh, add-criteria.sh, set-criterion.sh). Never hand-edits
# verify-results.json.
#
# Default is a DRY RUN: the calls are printed and nothing is written. --apply runs them. A task
# group that already exists gets only its missing criteria; an existing criterion is left alone
# (changes after approval go through scripts/new-addendum.sh).
#
# Syntax it reads (anything else in the file is prose):
#   ### TG-<nn> - <title> [ui] [risk: low|medium|high]   (both tags optional; risk defaults to medium)
#   - **P<n>-<AREA>-C<k>** [R-<AREA>-<i>, ...] {<classes>}: <EARS text>
#   - **P<n>-<AREA>-C<k>-<GATE>** [R-...] {live | gate: <TOKEN> | item: O<j>}: <gated half>
# Classes: test, http, screenshot, live, log. Gate tokens: EXTERNAL-SERVICE, DEPLOY, LABELLED-DATA,
# SIGN-OFF, PHASE-<n>-ENTRY.
#
# Refuses (nothing written): a criterion citing no register row; an unknown evidence class; a
# gated criterion with no gate token or an unknown one; a duplicate ID in the spec; a task group
# with no criteria; an ID that does not match the scheme. Notes (not refusals): a task group with
# more than eight criteria; a group with a register row cited by no criterion elsewhere is not
# checked here (the sign-off generator reports register coverage).
set -euo pipefail

USAGE='Usage: spec-to-contract.sh <phase-spec.md> [--apply] [--tg TG-nn] [--no-gates "<reason>"]'
SPEC="${1:?$USAGE}"; shift
APPLY=0; ONLY_TG=""; NO_GATES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --tg) ONLY_TG="${2:?--tg needs a task-group ID}"; shift ;;
    --no-gates) NO_GATES="${2:?--no-gates needs a written reason}"; shift ;;
    *) echo "$USAGE" >&2; exit 1 ;;
  esac
  shift
done
[[ -f "$SPEC" ]] || { echo "spec-to-contract: spec file not found: $SPEC" >&2; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$PROJECT_ROOT/_docs/ai/verify/verify-results.json"
SCRIPTS="$PROJECT_ROOT/scripts"
for h in new-task-group.sh add-criteria.sh set-criterion.sh; do
  [[ -f "$SCRIPTS/$h" ]] || { echo "spec-to-contract: $SCRIPTS/$h missing (delivered by bootstrap)." >&2; exit 1; }
done

PY=""; PY_ARGS=()
# Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
[[ -z "$PY" ]] && { echo "spec-to-contract: Python 3 is required (python3/python/py not found)." >&2; exit 1; }

# ---- parse + validate; emit one line per action: TG|<id>|<title>|<ui>  or  CR|<tg>|<id>|<classes>|<rows>|<gate>|<item>|<text>
PLAN="$(SPEC_PATH="$SPEC" RESULTS_PATH="$RESULTS" ONLY_TG_VAL="$ONLY_TG" pyc - <<'PYEOF'
import json, os, re, sys
spec = open(os.environ["SPEC_PATH"], encoding="utf-8").read()
only = os.environ.get("ONLY_TG_VAL", "")
CLASSES = {"test", "http", "screenshot", "live", "log"}
TOKENS = {"EXTERNAL-SERVICE", "DEPLOY", "LABELLED-DATA", "SIGN-OFF"}
TG_RE = re.compile(r"^###\s+(TG-\d{2,}[A-Z]?)\s*[-:]\s*(.+?)\s*$")
CR_RE = re.compile(r"^-\s+\*\*(P\d+-[A-Z]{3,4}-C\d+[a-z]?(?:-[A-Z][A-Z0-9-]*)?)\*\*\s*(.*)$")
ID_RE = re.compile(r"^P\d+-[A-Z]{3,4}-C\d+[a-z]?(-[A-Z][A-Z0-9-]*)?$")
existing = {}
try:
    data = json.load(open(os.environ["RESULTS_PATH"], encoding="utf-8"))
    for tg in data.get("taskGroups", []):
        existing[tg.get("id")] = {c.get("id") for c in tg.get("criteria", [])}
except (OSError, json.JSONDecodeError):
    pass
errors, notes, out = [], [], []
seen = set(); cur = None; counts = {}
for ln, raw in enumerate(spec.splitlines(), 1):
    line = raw.rstrip()
    if line.startswith("## ") and cur:
        cur = None            # a top-level heading ends the task-group section
    m = TG_RE.match(line)
    if m:
        tg_id, title = m.group(1), m.group(2)
        ui = "1" if re.search(r"\[ui\]", title) else "0"
        rm = re.search(r"\[risk:\s*(low|medium|high)\]", title)
        risk = rm.group(1) if rm else "medium"
        title = re.sub(r"\s*\[(ui|risk:\s*(low|medium|high))\]", "", title).strip()
        cur = tg_id
        if tg_id in counts:
            errors.append(f"line {ln}: task group {tg_id} appears twice"); continue
        counts[tg_id] = 0
        if not only or only == tg_id:
            out.append("TG|%s|%s|%s|%s|%s" % (tg_id, title, ui, "exists" if tg_id in existing else "new", risk))
        continue
    m = CR_RE.match(line)
    if not m:
        continue
    if cur is None:
        errors.append(f"line {ln}: criterion {m.group(1)} is not under a '### TG-nn - title' heading"); continue
    cid, rest = m.group(1), m.group(2).strip()
    counts[cur] += 1
    if not ID_RE.match(cid):
        errors.append(f"line {ln}: criterion ID '{cid}' does not match P<n>-<AREA>-C<k>[a][-GATE]"); continue
    if cid in seen:
        errors.append(f"line {ln}: duplicate criterion ID {cid}"); continue
    seen.add(cid)
    rows = re.match(r"^\[([^\]]*)\]", rest)
    if not rows:
        errors.append(f"line {ln}: {cid} cites no register row ([R-<AREA>-<n>] after the ID)"); continue
    row_ids = [r.strip() for r in rows.group(1).split(",") if r.strip()]
    if not row_ids or not all(re.match(r"^R-[A-Z]{3,4}-\d+$", r) for r in row_ids):
        errors.append(f"line {ln}: {cid} register citation '{rows.group(1)}' is not R-<AREA>-<n>[, ...]"); continue
    rest = rest[rows.end():].strip()
    braces = re.match(r"^\{([^}]*)\}", rest)
    if not braces:
        errors.append(f"line {ln}: {cid} has no evidence-class block ({{test, http, ...}})"); continue
    parts = [p.strip() for p in braces.group(1).split("|")]
    classes = [c.strip().lower() for c in parts[0].split(",") if c.strip()]
    bad = [c for c in classes if c not in CLASSES]
    if not classes or bad:
        errors.append(f"line {ln}: {cid} evidence class {bad or '(none)'} not in {sorted(CLASSES)}"); continue
    gate = item = ""
    for p in parts[1:]:
        k, _, v = p.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k == "gate": gate = v
        elif k == "item": item = v
        else: errors.append(f"line {ln}: {cid} unknown tag '{p}' (gate: / item:)")
    is_gated = bool(re.match(r"^P\d+-[A-Z]{3,4}-C\d+[a-z]?-", cid))
    if is_gated or gate:
        if not gate:
            errors.append(f"line {ln}: {cid} looks gated (suffix after C<k>) but names no 'gate: <TOKEN>'"); continue
        if not (gate in TOKENS or re.fullmatch(r"PHASE-\d+-ENTRY", gate)):
            errors.append(f"line {ln}: {cid} gate '{gate}' not in {sorted(TOKENS)} or PHASE-<n>-ENTRY"); continue
        if not item:
            notes.append(f"{cid}: gated with no 'item: O<j>' - the disposition will not name what clears it")
    rest = rest[braces.end():].strip()
    if rest.startswith(":"): rest = rest[1:].strip()
    if not rest:
        errors.append(f"line {ln}: {cid} has no criterion text after the colon"); continue
    if only and cur != only:
        continue
    out.append("CR|%s|%s|%s|%s|%s|%s|%s" % (cur, cid, ",".join(classes), ",".join(row_ids), gate, item, rest.replace("|", "/")))
for tg_id, n in counts.items():
    if n == 0: errors.append(f"task group {tg_id} has no criteria")
    if n > 8: notes.append(f"{tg_id} has {n} criteria (three to eight per group; split by sub-area)")
if not counts:
    errors.append("no '### TG-nn - title' headings found (phase-spec template, Section 4)")
if only and only not in counts:
    errors.append(f"--tg {only}: no such task group in the spec")
for n in notes: print("NOTE " + n, file=sys.stderr)
if errors:
    for e in errors: print("spec-to-contract: " + e, file=sys.stderr)
    sys.exit(2)
print("\n".join(out))
PYEOF
)" || { echo "spec-to-contract: refused - nothing written." >&2; exit 2; }

PLAN="${PLAN//$'\r'/}"   # Windows Python ends every printed line with CR; the last field would carry it
[[ -n "$PLAN" ]] || { echo "spec-to-contract: nothing to do." ; exit 0; }

run() { if [[ "$APPLY" == "1" ]]; then "$@"; else printf '  %q' "$@"; printf '\n'; fi; }

[[ "$APPLY" == "1" ]] || echo "spec-to-contract: DRY RUN (add --apply to write). Calls that would run:"
tg_new=0; cr_new=0; cr_gated=0; cr_skip=0
while IFS='|' read -r kind a b c d e f g; do
  case "$kind" in
    TG)
      if [[ "$d" == "exists" ]]; then
        echo "# $a exists in the contract - adding missing criteria only"
      else
        args=("$SCRIPTS/new-task-group.sh" "$a" "$b"); [[ "$c" == "1" ]] && args+=(--ui); [[ -n "$e" ]] && args+=(--risk "$e"); [[ -n "$NO_GATES" ]] && args+=(--no-gates "$NO_GATES")
        run bash "${args[@]}"; tg_new=$((tg_new+1))
      fi ;;
    CR)
      tg="$a"; cid="$b"; classes="$c"; rows="$d"; gate="$e"; item="$f"; text="$g"
      if [[ "$APPLY" == "1" ]] && RESULTS_PATH="$RESULTS" CID="$cid" "$PY" "${PY_ARGS[@]}" -c 'import json,os,sys; d=json.load(open(os.environ["RESULTS_PATH"],encoding="utf-8")); sys.exit(0 if any(c.get("id")==os.environ["CID"] for t in d.get("taskGroups",[]) for c in t.get("criteria",[])) else 1)' 2>/dev/null; then
        echo "# $cid already in the contract - unchanged (changes go through scripts/new-addendum.sh)"; cr_skip=$((cr_skip+1)); continue
      fi
      run bash "$SCRIPTS/add-criteria.sh" "$tg" "$cid" "$text"
      # the register's evidence class and rows travel with the row (verify-gate checks the class on PASS)
      if [[ "$APPLY" == "1" ]]; then
        RESULTS_PATH="$RESULTS" CID="$cid" CLASSES="$classes" ROWS="$rows" "$PY" "${PY_ARGS[@]}" - <<'PYEOF'
import json, os
p = os.environ["RESULTS_PATH"]; d = json.load(open(p, encoding="utf-8"))
for t in d.get("taskGroups", []):
    for c in t.get("criteria", []):
        if c.get("id") == os.environ["CID"]:
            c["evidenceClass"] = os.environ["CLASSES"].split(",")
            c["register"] = os.environ["ROWS"].split(",")
json.dump(d, open(p, "w", encoding="utf-8"), indent=2); open(p, "a", encoding="utf-8").write("\n")
PYEOF
      else
        echo "  # + evidenceClass=[$classes] register=[$rows]"
      fi
      if [[ -n "$gate" ]]; then
        disp="Gated half${item:+: waits on $item} (${rows}): ${text:0:140}"
        run bash "$SCRIPTS/set-criterion.sh" "$tg" "$cid" BLOCKED "$gate" "$disp"; cr_gated=$((cr_gated+1))
      fi
      cr_new=$((cr_new+1)) ;;
  esac
done <<< "$PLAN"

# the contract names its spec
if [[ "$APPLY" == "1" ]]; then
  RESULTS_PATH="$RESULTS" SPEC_NAME="$(basename "$SPEC")" pyc -c 'import json,os; p=os.environ["RESULTS_PATH"]; d=json.load(open(p,encoding="utf-8")); d["spec"]=d.get("spec") or os.environ["SPEC_NAME"]; json.dump(d,open(p,"w",encoding="utf-8"),indent=2); open(p,"a",encoding="utf-8").write("\n")'
  echo "spec-to-contract: $tg_new task group(s) opened, $cr_new criteria added FAIL-first ($cr_gated gated halves BLOCKED), $cr_skip already present. Next: scripts/verify-gate.sh --verbose"
else
  echo "spec-to-contract: $tg_new task group(s) to open, $cr_new criteria to add ($cr_gated gated halves). Nothing written."
fi
