#!/usr/bin/env bash
# check.sh <name>|--all [--list]
#
# Runs one declared check quietly and records the result where the gate can read it.
# Declared checks live in _docs/ai/verify/checks.env (stamped by bootstrap from the template;
# the project edits it): TEST, BUILD, LINT, TYPECHECK, and optionally BOOT_PROBE (a URL that
# must answer 2xx/3xx) and DEPENDENCY_CHECK (a command). An absent or empty file declares
# nothing, and the gate then requires nothing.
#
# For each check: the real command runs, its FULL output goes to
# _docs/ai/logs/check-<name>-<stamp>.log, and three places get the SUMMARY only:
#   stdout                                       PASS: 417 tests      or   FAIL: 2 + failing lines
#   _docs/ai/verify/evidence/CHECK-<name>.<ext>  the evidence file (testresults.txt for TEST, .log otherwise)
#   _docs/ai/verify/checks-state.json            {commit, at, results{name:{status, summary, log, at}}}
# A test runner printing four hundred green lines leaves four hundred lines in the model's
# context for every later turn; the summary is what the model needs, the log is on disk.
#
# Runner summaries understood: dotnet test (classic and the newer "Test summary" form),
# vitest, jest, pytest, go test, mocha. Anything else: exit code, and on failure the lines
# that look like errors (at most 20) or the last 20 lines.
# Exit code: the command's. The gate treats a closed task group as complete only when every
# declared check is PASS at HEAD (scripts/verify-gate.sh, [CHECKS]).
set -uo pipefail

USAGE='Usage: check.sh <TEST|BUILD|LINT|TYPECHECK|BOOT_PROBE|DEPENDENCY_CHECK|name> | --all | --list'
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY_DIR="$PROJECT_ROOT/_docs/ai/verify"
CHECKS_ENV="$VERIFY_DIR/checks.env"
STATE="$VERIFY_DIR/checks-state.json"
LOG_DIR="$PROJECT_ROOT/_docs/ai/logs"
EVIDENCE_DIR="$VERIFY_DIR/evidence"

PY=""; PY_ARGS=()
# Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
[[ -z "$PY" ]] && { echo "check: Python 3 is required (python3/python/py not found)." >&2; exit 1; }

# ---- read checks.env: NAME="command" lines; comments and blanks ignored
# parallel arrays (bash 3.2 on macOS has no associative arrays)
ORDER=(); CMDS=()
cmd_of() { local i; for i in "${!ORDER[@]}"; do [[ "${ORDER[$i]}" == "$1" ]] && { printf '%s' "${CMDS[$i]}"; return 0; }; done; return 1; }
if [[ -f "$CHECKS_ENV" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*# || -z "${line//[[:space:]]/}" ]] && continue
    name="${line%%=*}"; value="${line#*=}"
    name="$(printf '%s' "$name" | tr -d '[:space:]')"
    value="${value#"${value%%[![:space:]]*}"}"; value="${value%"${value##*[![:space:]]}"}"
    [[ "$value" == \"*\" ]] && value="${value#\"}" && value="${value%\"}"
    [[ "$value" == \'*\' ]] && value="${value#\'}" && value="${value%\'}"
    [[ -n "$name" && -n "$value" ]] || continue
    ORDER+=("$name"); CMDS+=("$value")
  done < "$CHECKS_ENV"
fi

case "${1:-}" in
  --list) for i in "${!ORDER[@]}"; do printf '%s=%s\n' "${ORDER[$i]}" "${CMDS[$i]}"; done; exit 0 ;;
  --all) NAMES=("${ORDER[@]}") ;;
  "") echo "$USAGE" >&2; exit 1 ;;
  *) NAMES=("$1") ;;
esac
[[ ${#NAMES[@]} -gt 0 ]] || { echo "check: nothing declared in _docs/ai/verify/checks.env (nothing to run, nothing required)."; exit 0; }

mkdir -p "$LOG_DIR" "$EVIDENCE_DIR"
HEAD_SHA="$(git -C "$PROJECT_ROOT" rev-parse --verify --quiet HEAD 2>/dev/null || echo "")"
overall=0
for name in "${NAMES[@]}"; do
  cmd="$(cmd_of "$name" || true)"
  [[ -n "$cmd" ]] || { echo "check: '$name' is not declared in _docs/ai/verify/checks.env" >&2; overall=1; continue; }
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  log="$LOG_DIR/check-$(printf '%s' "$name" | tr 'A-Z' 'a-z')-$stamp.log"
  lname="$(printf '%s' "$name" | tr 'A-Z' 'a-z')"
  if [[ "$name" == "BOOT_PROBE" ]]; then
    # a URL that must answer; the "command" is the URL
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$cmd" 2>>"$log" || echo "000")"
    printf 'GET %s -> %s\n' "$cmd" "$code" >> "$log"
    if [[ "$code" =~ ^[23][0-9][0-9]$ ]]; then rc=0; else rc=1; fi
  else
    ( cd "$PROJECT_ROOT" && bash -c "$cmd" ) > "$log" 2>&1; rc=$?
  fi
  summary="$(LOG_PATH="$log" ROOT_PATH="$PROJECT_ROOT" CMD="$cmd" NAME="$name" RC="$rc" pyc - <<'PYEOF'
import os, re, sys
log = open(os.environ["LOG_PATH"], encoding="utf-8", errors="replace").read()
lines = log.splitlines()
cmd = os.environ["CMD"]; name = os.environ["NAME"]; rc = int(os.environ["RC"])
low = cmd.lower()
def num(m, i=1):
    try: return int(m.group(i))
    except Exception: return None
total = passed = failed = None; fails = []
runner = None
# ---- dotnet test
m = re.search(r"Passed!\s+-\s+Failed:\s+(\d+),\s+Passed:\s+(\d+),\s+Skipped:\s+(\d+),\s+Total:\s+(\d+)", log) or \
    re.search(r"Failed!\s+-\s+Failed:\s+(\d+),\s+Passed:\s+(\d+),\s+Skipped:\s+(\d+),\s+Total:\s+(\d+)", log)
if m:
    runner = "dotnet"; failed, passed, total = num(m,1), num(m,2), num(m,4)
m2 = re.search(r"Test summary:\s*total:\s*(\d+),\s*failed:\s*(\d+),\s*succeeded:\s*(\d+)", log)
if m2:
    runner = "dotnet"; total, failed, passed = num(m2,1), num(m2,2), num(m2,3)
if runner == "dotnet":
    for i, l in enumerate(lines):
        mm = re.match(r"^\s*(?:Failed|failed)\s+(\S.*?)\s*(?:\[\d+\s*m?s\]|\(\d+\s*m?s\))\s*$", l)
        if mm:
            detail = ""
            for j in range(i+1, min(i+8, len(lines))):
                if "Error Message" in lines[j] and j+1 < len(lines):
                    detail = lines[j+1].strip(); break
                if lines[j].strip().startswith(("Assert.", "Expected", "expected")):
                    detail = lines[j].strip(); break
            fails.append(f"{mm.group(1).strip()}: {detail}".rstrip(": "))
# ---- vitest
m = re.search(r"^\s*Tests\s+(?:(\d+)\s+failed\s*\|\s*)?(\d+)\s+passed(?:\s*\|\s*\d+\s+skipped)?\s*\((\d+)\)", log, re.M)
if m and runner is None:
    runner = "vitest"; failed = num(m,1) or 0; passed = num(m,2); total = num(m,3)
    for i, l in enumerate(lines):
        mm = re.match(r"^\s*(?:FAIL|×|x)\s+(\S+\.(?:test|spec)\.[a-z]+)\s*>\s*(.+?)\s*$", l)
        if mm:
            detail = ""
            for j in range(i+1, min(i+12, len(lines))):
                if re.search(r"(AssertionError|Error:|expected)", lines[j]):
                    detail = lines[j].strip(); break
            loc = ""
            for j in range(i+1, min(i+30, len(lines))):
                ml = re.search(r"(\S+\.(?:test|spec)\.[a-z]+):(\d+)", lines[j])
                if ml: loc = f"{ml.group(1)}:{ml.group(2)}"; break
            fails.append(f"{loc or mm.group(1)} {mm.group(2)}: {detail}".strip().rstrip(":"))
# ---- jest
m = re.search(r"^Tests:\s+(?:(\d+)\s+failed,\s+)?(?:\d+\s+skipped,\s+)?(\d+)\s+passed,\s+(\d+)\s+total", log, re.M)
if m and runner is None:
    runner = "jest"; failed = num(m,1) or 0; passed = num(m,2); total = num(m,3)
    for i, l in enumerate(lines):
        mm = re.match(r"^\s*●\s+(.+?)\s*$", l)
        if mm and "Test suite failed" not in l:
            detail = ""; loc = ""
            for j in range(i+1, min(i+25, len(lines))):
                if not detail and re.search(r"(expect\(|Expected|Received|Error:)", lines[j]): detail = lines[j].strip()
                ml = re.search(r"\(?(\S+\.(?:test|spec)\.[a-z]+):(\d+)", lines[j])
                if ml and not loc: loc = f"{ml.group(1)}:{ml.group(2)}"
                if detail and loc: break
            fails.append(f"{loc} {mm.group(1)}: {detail}".strip().rstrip(":"))
# ---- pytest
m = re.search(r"=+\s+(?:(\d+)\s+failed,?\s*)?(?:(\d+)\s+passed)?(?:,\s*\d+\s+(?:skipped|deselected|xfailed|warnings?))*\s+in\s+[\d.]+s", log)
if m and runner is None and (m.group(1) or m.group(2)):
    runner = "pytest"; failed = num(m,1) or 0; passed = num(m,2) or 0; total = failed + passed
    for l in lines:
        mm = re.match(r"^FAILED\s+(\S+)(?:\s+-\s+(.*))?$", l)
        if mm: fails.append(f"{mm.group(1)}: {mm.group(2) or ''}".rstrip(": "))
# ---- go test
if runner is None and (low.startswith("go test") or re.search(r"^(ok|FAIL|---\s+FAIL)\s", log, re.M)):
    oks = len(re.findall(r"^ok\s+\S+", log, re.M)); fl = re.findall(r"^---\s+FAIL:\s+(\S+)", log, re.M)
    if oks or fl or re.search(r"^FAIL\s", log, re.M):
        runner = "go"; failed = len(fl); passed = oks; total = None
        for i, l in enumerate(lines):
            mm = re.match(r"^---\s+FAIL:\s+(\S+)", l)
            if mm:
                detail = ""
                for j in range(i+1, min(i+6, len(lines))):
                    ml = re.search(r"(\S+_test\.go:\d+):\s*(.*)", lines[j])
                    if ml: detail = f"{ml.group(1)} {ml.group(2)}"; break
                fails.append(f"{mm.group(1)}: {detail}".rstrip(": "))
# ---- mocha
m = re.search(r"^\s*(\d+)\s+passing", log, re.M)
if m and runner is None:
    runner = "mocha"; passed = num(m,1); mf = re.search(r"^\s*(\d+)\s+failing", log, re.M); failed = num(mf,1) if mf else 0; total = passed + failed
    for l in lines:
        mm = re.match(r"^\s*\d+\)\s+(.+?)\s*$", l)
        if mm: fails.append(mm.group(1))
# ---- compiler / lint diagnostics as failure lines for non-test checks
if runner is None:
    diag = []
    for l in lines:
        if re.search(r"(^|\s)error(\s|:|\s*[A-Z]{2}\d{3,5}|\[)|\bERROR\b|\bFAIL(ED)?\b|✖|× ", l) and len(l.strip()) > 3:
            diag.append(l.strip())
    fails = diag[:20] if rc != 0 else []
ok = (rc == 0) and not (failed and failed > 0)
if runner and failed is not None and failed > 0: ok = False
lname = name.lower()
if ok:
    if runner and passed is not None:
        head = f"PASS: {passed} tests" + (f" ({runner})" if runner else "")
    elif name == "BOOT_PROBE":
        head = f"PASS: {name.lower()} answered"
    else:
        head = f"PASS: {lname}"
    body = []
else:
    if runner and failed is not None:
        head = f"FAIL: {failed}" + (f" of {total}" if total else "") + (f" ({runner})" if runner else "")
    elif rc != 0:
        head = f"FAIL: {lname} (exit {rc})"
    else:
        head = f"FAIL: {lname}"
    body = [f for f in fails if f][:20] or [l for l in lines if l.strip()][-20:]
print(head)
for b in body: print(b)
root = os.environ.get("ROOT_PATH") or os.getcwd()
print("log: " + os.path.relpath(os.environ["LOG_PATH"], root).replace("\\", "/"))
sys.exit(0 if ok else 1)
PYEOF
)"; srcrc=$?
  summary="${summary//$'\r'/}"   # Windows Python prints CRLF; the state file and the gate compare these lines
  status="PASS"; [[ "$srcrc" -eq 0 ]] || { status="FAIL"; overall=1; }
  # evidence file: TEST -> testresults.txt (class "test"); everything else -> .log
  if [[ "$name" == "TEST" ]]; then ev="$EVIDENCE_DIR/CHECK-test.testresults.txt"; else ev="$EVIDENCE_DIR/CHECK-$lname.log"; fi
  # the witnessed run itself (one invocation per file by construction), with a footer naming the
  # command, the commit and the time; the summary is derived from it, never stored instead of it
  {
    cat "$log"
    printf '\ncommand: %s\ncommit: %s\nat: %s\n' "$cmd" "${HEAD_SHA:-none}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$ev"
  printf '%s\n' "$summary"
  # state file (merged per check)
  STATE_PATH="$STATE" ROOT_PATH="$PROJECT_ROOT" NAME="$name" STATUS="$status" SUMMARY="$(printf '%s' "$summary" | head -1)" LOG_PATH="$log" EV_PATH="$ev" HEAD_VAL="${HEAD_SHA:-}" pyc - <<'PYEOF'
import json, os, time
p = os.environ["STATE_PATH"]
try:
    d = json.load(open(p, encoding="utf-8"))
except Exception:
    d = {}
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
d["commit"] = os.environ.get("HEAD_VAL") or None
d["at"] = now
d["atEpoch"] = time.time()
d.setdefault("results", {})[os.environ["NAME"]] = {
    "status": os.environ["STATUS"], "summary": os.environ["SUMMARY"],
    "log": os.path.relpath(os.environ["LOG_PATH"], os.environ["ROOT_PATH"]).replace("\\", "/"),
    "evidence": os.path.basename(os.environ["EV_PATH"]), "at": now, "commit": os.environ.get("HEAD_VAL") or None,
}
json.dump(d, open(p, "w", encoding="utf-8"), indent=2); open(p, "a", encoding="utf-8").write("\n")
PYEOF
done
exit "$overall"
