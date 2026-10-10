#!/usr/bin/env bash
# verify-gate.sh - Tier B validator for the evidence-gated completion contract.
# Validates _docs/ai/verify/verify-results.json against the evidence contract.
# Exit 0 = gate passes. Exit 1 = gate fails (offending criteria listed on stderr).
#
# Lineage: v1.8.1-cc (Python engine, BLOCKED), v1.10.0 (ui flag + gate tokens),
# v1.11.0 (red baseline + --gates), v3.0.0 (this edition - see the CHANGELOG [3.0.0]):
#   - VACUOUS-GATE GUARD: zero recorded criteria + application code in the diff = FAIL,
#     unless a dated top-level "noTaskGroupsExemption" (gate BOOTSTRAP) is present.
#     An empty taskGroups list passed every commit on a real project for months (harvest
#     2026-09); the one enforcement layer that fires everywhere had never checked anything.
#   - QUIET OUTPUT: one summary line by default; GATE NOTEs for long-standing BLOCKED rows
#     only with --verbose (a 34-row project paid ~3,300 tokens per commit for unchanged
#     notes). Exemptions (RED-EXEMPT, BOOTSTRAP) are always printed - they are the loud part.
#   - RED COMMIT ORDER: red baseline must be committed before the first PASS evidence when
#     git knows both; red and green landing uncommitted together is reported UNVERIFIABLE.
#   - startedAt is REQUIRED on any task group with PASS criteria (it used to pass silently).
#   - ".live." evidence: a ui-flagged group needs at least one deployed-environment capture
#     (a filename carrying ".live.") unless a criterion in the group is BLOCKED on DEPLOY.
#   - ADDENDUM cross-check (warning): a criterion carrying "addendumAt" with no test-path
#     change since that date prints a GATE NOTE - a ruling in a spec is not a fix to the tree.
#   - Gate 0.5 (Repository standards) is a recognised gate id in --gates mode.
#
# Usage:
#   scripts/verify-gate.sh                 # validate the whole file (phase-exit / pre-commit / CI)
#   scripts/verify-gate.sh --file P        # validate a specific results file (used by hooks)
#   scripts/verify-gate.sh --tg TG-01      # validate a single task group
#   scripts/verify-gate.sh --gates         # validate gate-state.json instead
#   scripts/verify-gate.sh --verbose       # print every BLOCKED row's GATE NOTE
#   scripts/verify-gate.sh --run           # run the declared checks (scripts/check.sh --all) first
# v3.3.0 (Truer Gates II):
#   [CHECKS]        a task group with no FAIL rows (a closed group, a completion claim) requires
#                   every check declared in _docs/ai/verify/checks.env to be PASS in
#                   checks-state.json at HEAD (or HEAD's parent, the tree that became the
#                   commit); locally, no app-code path may be newer than the run. An empty or
#                   absent checks.env declares nothing and requires nothing.
#   [TEST-MODIFIED] a test file that existed at the red-baseline commit and was modified or
#                   deleted since (committed or in the working tree) fails the gate unless the
#                   group records allowTestChange (set-criterion.sh --allow-test-change, or the
#                   --addendum marker). Additions are free. The implementer's test-integrity
#                   clause becomes a check, not a request.
# Environment:
#   VERIFY_GATE_SCOPE=staged|worktree|range   diff scope for the vacuous-gate guard
#     (pre-commit hook sets staged; CI sets range via VERIFY_GATE_DIFF_RANGE; default worktree)
#   VERIFY_GATE_DIFF_RANGE="<base> <head>"    explicit git diff range (CI workflows set the PR base)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$PROJECT_ROOT/_docs/ai/verify/verify-results.json"
EVIDENCE_DIR="$PROJECT_ROOT/_docs/ai/verify/evidence"
APP_PATHS_FILE="$PROJECT_ROOT/_docs/ai/verify/app-code-paths"
TG_FILTER=""
GATES_MODE="0"
VERBOSE="0"
RUN_CHECKS="0"
GATE_STATE="$PROJECT_ROOT/_docs/ai/verify/gate-state.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --file) RESULTS="${2:?--file requires a path}"; shift 2 ;;
    --tg)   TG_FILTER="${2:?--tg requires a task-group id}"; shift 2 ;;
    --gates) GATES_MODE="1"; shift ;;
    --verbose) VERBOSE="1"; shift ;;
    --run) RUN_CHECKS="1"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

PY=""; PY_ARGS=()
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  # Reject non-functional interpreters (e.g. the Windows Store python3 alias stub)
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
if [[ -z "$PY" ]]; then
  echo "verify-gate: Python 3 is required (python3/python/py not found on PATH)." >&2
  echo "The evidence gate cannot run without it; install Python before making completion claims." >&2
  exit 1
fi

# v1.11.0 (Rec 2): --gates validates gate-state.json instead of the criteria file.
if [[ "$GATES_MODE" == "1" ]]; then
  GATE_STATE_PATH="$GATE_STATE" PROJECT_ROOT_PATH="$PROJECT_ROOT" "$PY" "${PY_ARGS[@]}" - <<'GEOF'
import json, os, sys
path = os.environ["GATE_STATE_PATH"]; root = os.environ["PROJECT_ROOT_PATH"]
CONDITIONAL = {"3", "4.5", "6.5", "7.5"}
try:
    data = json.load(open(path, encoding="utf-8"))
except FileNotFoundError:
    print("gate-check: gate-state.json not found - gate sequence has not been run "
          "(create from _docs/ai/verify/gate-state.example.json; see skills/gate-sequence).", file=sys.stderr)
    sys.exit(1)
except json.JSONDecodeError as exc:
    print(f"gate-check: gate-state.json invalid JSON: {exc}", file=sys.stderr); sys.exit(1)
fails = 0
def fail(gid, msg):
    global fails; print(f"GATE-STATE FAIL [{gid}]: {msg}", file=sys.stderr); fails += 1
gates = {str(g.get("id")): g for g in data.get("gates", [])}
for gid, g in gates.items():
    st = g.get("status")
    if st not in ("PASS", "FAIL", "NA", "EXEMPT", "PENDING"):
        fail(gid, f"illegal status '{st}'"); continue
    if st == "NA" and gid not in CONDITIONAL:
        fail(gid, "NA is legal only for conditional gates (3, 4.5, 6.5, 7.5)")
    if st == "EXEMPT" and not (g.get("note") or "").strip():
        fail(gid, "EXEMPT without a written justification in 'note'")
    if st == "PASS":
        art = (g.get("artefact") or "").strip()
        if not art:
            fail(gid, "PASS without a declared artefact")
        else:
            ap = os.path.join(root, art)
            if not os.path.isfile(ap) or os.path.getsize(ap) == 0:
                fail(gid, f"artefact '{art}' missing or empty")
g8 = gates.get("8")
if g8 and g8.get("status") == "PASS":
    for gid, g in gates.items():
        if gid != "8" and g.get("status") not in ("PASS", "NA", "EXEMPT"):
            fail("8", f"Gate 8 is PASS but gate {gid} is {g.get('status')}")
    # v3.0.0: Gate 0.5 (Repository standards) is part of the sequence - a gate-state that
    # predates it is reported, not failed, so migrated projects see the gap at every run.
    if "0.5" not in gates:
        print("GATE-STATE NOTE: Gate 0.5 (Repository standards) is absent from gate-state.json - "
              "add it from gate-state.example.json and walk it (skills/gate-sequence).", file=sys.stderr)
# v3.0.0: EXEMPT rows with a reviewBy date are re-examined when the date passes.
from datetime import date
for gid, g in gates.items():
    rb = (g.get("reviewBy") or "").strip()
    if g.get("status") == "EXEMPT" and rb:
        try:
            if date.fromisoformat(rb) < date.today():
                print(f"GATE-STATE NOTE [{gid}]: EXEMPT past its reviewBy date ({rb}) - re-decide or extend.", file=sys.stderr)
        except ValueError:
            fail(gid, f"reviewBy '{rb}' is not an ISO date (YYYY-MM-DD)")
if fails:
    print(f"gate-check: {fails} violation(s).", file=sys.stderr); sys.exit(1)
n = sum(1 for g in gates.values() if g.get("status") == "PASS")
print(f"gate-check: PASS ({n} gates PASS of {len(gates)}; Gate 8: {gates.get('8',{}).get('status','absent')})")
GEOF
  exit $?
fi

if [[ ! -f "$RESULTS" ]]; then
  echo "verify-gate: results file not found: $RESULTS" >&2
  echo "A project under the v1.7+ contract must have verify-results.json before completion claims." >&2
  exit 1
fi

# ------------------------------------------------------------------
# Changed-file list for the vacuous-gate guard (v3.0.0). Computed in bash so the Python
# validator stays free of subprocess plumbing; empty when git is unavailable (the guard
# then reports itself as SKIPPED rather than silently passing).
# ------------------------------------------------------------------
CHANGED_FILES=""
DIFF_SOURCE="none"
if git -C "$PROJECT_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  _scope="${VERIFY_GATE_SCOPE:-}"
  if [[ -n "${VERIFY_GATE_DIFF_RANGE:-}" ]]; then
    _scope="range"
  elif [[ -z "$_scope" ]]; then
    if [[ -n "${CI:-}${GITHUB_ACTIONS:-}${TF_BUILD:-}" ]]; then _scope="ci"; else _scope="worktree"; fi
  fi
  case "$_scope" in
    staged)
      CHANGED_FILES="$(git -C "$PROJECT_ROOT" diff --cached --name-only 2>/dev/null || true)"; DIFF_SOURCE="staged" ;;
    range)
      # shellcheck disable=SC2086
      CHANGED_FILES="$(git -C "$PROJECT_ROOT" diff --name-only $VERIFY_GATE_DIFF_RANGE 2>/dev/null || true)"; DIFF_SOURCE="range:$VERIFY_GATE_DIFF_RANGE" ;;
    ci)
      CHANGED_FILES="$(git -C "$PROJECT_ROOT" diff --name-only HEAD^ HEAD 2>/dev/null || true)"; DIFF_SOURCE="ci:HEAD^..HEAD" ;;
    *)
      CHANGED_FILES="$( { git -C "$PROJECT_ROOT" diff --name-only HEAD 2>/dev/null; git -C "$PROJECT_ROOT" ls-files --others --exclude-standard 2>/dev/null; } | sort -u || true)"; DIFF_SOURCE="worktree" ;;
  esac
fi

# v3.3.0: --run executes the declared checks through the quiet wrapper before validating.
if [[ "$RUN_CHECKS" == "1" ]]; then
  if [[ -f "$PROJECT_ROOT/scripts/check.sh" ]]; then
    bash "$PROJECT_ROOT/scripts/check.sh" --all || echo "verify-gate: one or more declared checks FAILED (details above; full logs in _docs/ai/logs/)." >&2
  else
    echo "verify-gate: --run needs scripts/check.sh (delivered by bootstrap --refresh-hooks)." >&2
  fi
fi

# Tier A (--file: a PROPOSED write handed over by the PreToolUse hook) validates content, not the
# commit; the change-set guard is skipped there so an agent can still write an empty contract
# after archiving a spec. Every other caller (pre-commit, CI, archive-spec, postcheck) runs it.
FILE_MODE="0"; [[ "$RESULTS" != "$PROJECT_ROOT/_docs/ai/verify/verify-results.json" ]] && FILE_MODE="1"

RESULTS_PATH="$RESULTS" EVIDENCE_DIR_PATH="$EVIDENCE_DIR" TG_FILTER_VAL="$TG_FILTER" FILE_MODE_VAL="$FILE_MODE" \
APP_PATHS_FILE_VAL="$APP_PATHS_FILE" CHANGED_FILES_VAL="$CHANGED_FILES" DIFF_SOURCE_VAL="$DIFF_SOURCE" \
VERBOSE_VAL="$VERBOSE" PROJECT_ROOT_VAL="$PROJECT_ROOT" \
"$PY" "${PY_ARGS[@]}" - <<'PYEOF'
import json, os, re, subprocess, sys
from datetime import datetime, timezone, date

results_path = os.environ["RESULTS_PATH"]
evidence_dir = os.environ["EVIDENCE_DIR_PATH"]
tg_filter = os.environ.get("TG_FILTER_VAL", "")
project_root = os.environ["PROJECT_ROOT_VAL"]
verbose = os.environ.get("VERBOSE_VAL") == "1"
file_mode = os.environ.get("FILE_MODE_VAL") == "1"
changed = [l.strip().replace("\\", "/") for l in os.environ.get("CHANGED_FILES_VAL", "").splitlines() if l.strip()]
diff_source = os.environ.get("DIFF_SOURCE_VAL", "none")
is_git = diff_source != "none"

ALLOWED = re.compile(r"\.(png|log|testresults\.txt|http\.txt|uatresults\.txt)$")

# v3.2.0: evidence names are CONTAINED in the evidence root. A name that is absolute, climbs
# with "..", or resolves outside the root is refused: a PASS could otherwise point at any file
# on the machine (or at another group's evidence) and satisfy the existence check.
_EV_ROOT = os.path.realpath(evidence_dir)
def contained(name):
    """Return the resolved path when name is a plain relative name inside the evidence root, else None."""
    if not isinstance(name, str) or not name.strip():
        return None
    n = name.strip().replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n) or n.startswith("~"):
        return None
    if any(part in ("..", "") for part in n.split("/")[:-1]) or n.split("/")[-1] == "..":
        return None
    p = os.path.realpath(os.path.join(_EV_ROOT, n))
    if p == _EV_ROOT or not p.startswith(_EV_ROOT + os.sep):
        return None
    return p
ALLOWED_DESC = "png|log|testresults.txt|http.txt|uatresults.txt"
EVIDENCE_CLASS_MATCH = {
    "test":       lambda n: n.endswith(".testresults.txt") or n.endswith(".uatresults.txt"),
    "http":       lambda n: n.endswith(".http.txt"),
    "screenshot": lambda n: n.endswith(".png"),
    "live":       lambda n: ".live." in n,
    "log":        lambda n: n.endswith(".log"),
}
EVIDENCE_CLASS_DESC = {
    "test": "*.testresults.txt or *.uatresults.txt", "http": "*.http.txt",
    "screenshot": "*.png", "live": "<ID>.live.*", "log": "*.log",
}
UAT = re.compile(r"\.uatresults\.txt$")
LIVE = re.compile(r"\.live\.")
GATE_TOKENS = {"EXTERNAL-SERVICE", "DEPLOY", "LABELLED-DATA", "SIGN-OFF"}
# The vacuous-gate exemption has its OWN token: BOOTSTRAP never enters the BLOCKED set above.
EXEMPTION_TOKEN = "BOOTSTRAP"
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs)/|\.(test|spec)\.[a-z]+$|Tests?\.cs$|_test\.(go|py)$")
IN_CI = any(os.environ.get(v) for v in ("CI", "GITHUB_ACTIONS", "TF_BUILD"))

try:
    with open(results_path, encoding="utf-8") as fh:
        data = json.load(fh)
except (OSError, json.JSONDecodeError) as exc:
    print(f"verify-gate: verify-results.json unreadable or invalid JSON: {exc}", file=sys.stderr)
    sys.exit(1)

failures = 0
blocked = []      # (tg, cid, text) - BLOCKED rows with disposition (verbose only)
exemptions = []   # (tg, cid, text) - always printed: RED-EXEMPT, BOOTSTRAP, UNVERIFIABLE, ADDENDUM

def fail(tg, cid, msg):
    global failures
    print(f"GATE FAIL [{tg}/{cid}]: {msg}", file=sys.stderr)
    failures += 1

def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def git_first_commit_epoch(relpath):
    """Epoch of the commit that first ADDED relpath, or None if untracked/unknown."""
    try:
        out = subprocess.run(["git", "-C", project_root, "log", "--diff-filter=A", "--format=%ct", "--", relpath],
                             capture_output=True, text=True, check=False, timeout=20).stdout.split()
        return int(out[-1]) if out else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None

def git_test_change_since(iso_date):
    """True if any test-path file changed in a commit at or after iso_date."""
    try:
        out = subprocess.run(["git", "-C", project_root, "log", f"--since={iso_date}", "--name-only", "--format="],
                             capture_output=True, text=True, check=False, timeout=20).stdout.splitlines()
        return any(TEST_PATH.search(l.strip().replace("\\", "/")) for l in out if l.strip())
    except (OSError, subprocess.SubprocessError):
        return None

def git_head():
    try:
        return subprocess.run(["git", "-C", project_root, "rev-parse", "HEAD"], capture_output=True, text=True, check=False, timeout=20).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None

def git_is_ancestor(a, b):
    try:
        return subprocess.run(["git", "-C", project_root, "merge-base", "--is-ancestor", a, b], capture_output=True, text=True, check=False, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False

def git_first_commit_sha(relpath):
    """Sha of the commit that first ADDED relpath, or None."""
    try:
        out = subprocess.run(["git", "-C", project_root, "log", "--diff-filter=A", "--format=%H", "--", relpath],
                             capture_output=True, text=True, check=False, timeout=20).stdout.split()
        return out[-1] if out else None
    except (OSError, subprocess.SubprocessError):
        return None

def git_test_files_changed_since(sha):
    """Test-path files MODIFIED or DELETED since sha (committed or in the working tree); additions are free."""
    changed = []
    try:
        for args in (["diff", "--name-status", f"{sha}..HEAD"], ["diff", "--name-status", "HEAD"]):
            out = subprocess.run(["git", "-C", project_root] + args, capture_output=True, text=True, check=False, timeout=20).stdout.splitlines()
            for l in out:
                parts = l.strip().split("\t")
                if len(parts) < 2: continue
                status, path = parts[0][:1], parts[-1].replace("\\", "/")
                if status in ("M", "D", "R") and TEST_PATH.search(path) and path not in changed:
                    changed.append(path)
    except (OSError, subprocess.SubprocessError):
        return None
    return changed

def load_app_prefixes():
    prefixes = []
    if os.path.isfile(os.environ["APP_PATHS_FILE_VAL"]):
        for line in open(os.environ["APP_PATHS_FILE_VAL"], encoding="utf-8"):
            line = line.strip().replace("\\", "/")
            if line and not line.startswith("#"):
                prefixes.append(line if line.endswith("/") else line + "/")
    if not prefixes:
        prefixes = ["src/", "app/", "lib/", "components/", "pages/", "api/", "services/",
                    "supabase/migrations/", "android/", "ios/"]
    return prefixes
app_prefixes = load_app_prefixes()

# v3.3.0: declared checks (scripts/check.sh) - loaded once; required for closed groups.
def load_checks():
    env_path = os.path.join(project_root, "_docs", "ai", "verify", "checks.env")
    names = []
    if os.path.isfile(env_path):
        for raw in open(env_path, encoding="utf-8", errors="replace"):
            raw = raw.strip()
            if not raw or raw.startswith("#") or "=" not in raw: continue
            k, v = raw.split("=", 1)
            if k.strip() and v.strip().strip("\"\'"): names.append(k.strip())
    state = {}
    sp = os.path.join(project_root, "_docs", "ai", "verify", "checks-state.json")
    if os.path.isfile(sp):
        try:
            state = json.load(open(sp, encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
    return names, state
DECLARED_CHECKS, CHECKS_STATE = load_checks()
_checks_verdict = None   # computed once, applied to every closed group
_no_checks_said = False  # the opt-out line prints once per run
def checks_problems():
    """List of [CHECKS] problems, empty when every declared check is PASS at HEAD and nothing app-side is newer."""
    global _checks_verdict
    if _checks_verdict is not None: return _checks_verdict
    probs = []
    if DECLARED_CHECKS:
        results = CHECKS_STATE.get("results") or {}
        for n in DECLARED_CHECKS:
            r = results.get(n)
            if not r:
                probs.append(f"{n} never run (scripts/verify-gate.sh --run, or scripts/check.sh {n})")
            elif r.get("status") != "PASS":
                probs.append(f"{n}: {r.get('summary', '')} (log: {r.get('log', '?')})")
        head = git_head() if is_git else None
        sc = CHECKS_STATE.get("commit")
        if results and head and sc:
            ok_commit = (sc == head)
            if not ok_commit:
                try:
                    parent = subprocess.run(["git", "-C", project_root, "rev-parse", "HEAD^"], capture_output=True, text=True, check=False, timeout=20).stdout.strip()
                    ok_commit = (sc == parent)
                except (OSError, subprocess.SubprocessError):
                    pass
            if not ok_commit and IN_CI:
                ok_commit = git_is_ancestor(sc, head)
            if not ok_commit:
                probs.append(f"not run at HEAD {head[:7]} (last run at {sc[:7]}); commits since the run need scripts/verify-gate.sh --run")
        if results and not IN_CI:
            at = parse_ts(CHECKS_STATE.get("at") or "")
            at_epoch = CHECKS_STATE.get("atEpoch")
            if not isinstance(at_epoch, (int, float)) and at is not None:
                at_epoch = at.timestamp() + 1.0   # second-precision stamp: tolerate the same second
            if at_epoch is not None:
                newer = []
                for prefix in app_prefixes:
                    base = os.path.join(project_root, prefix)
                    if os.path.isfile(base):
                        if os.path.getmtime(base) > at_epoch: newer.append(prefix)
                        continue
                    for root_, _d, files_ in os.walk(base):
                        if "node_modules" in root_ or "/." in root_.replace("\\", "/"): continue
                        for f in files_:
                            fp = os.path.join(root_, f)
                            try:
                                if os.path.getmtime(fp) > at_epoch and not TEST_PATH.search(fp.replace("\\", "/")):
                                    newer.append(os.path.relpath(fp, project_root).replace("\\", "/")); break
                            except OSError:
                                pass
                        if newer and newer[-1].startswith(prefix): break
                if newer:
                    probs.append(f"application code modified after the last run ({newer[0]}{' ...' if len(newer) > 1 else ''}); re-run scripts/verify-gate.sh --run")
    _checks_verdict = probs
    return probs

# ------------------------------------------------------------------
# v3.0.0: the vacuous-gate guard. A contract with zero criteria is indistinguishable from a
# fully-evidenced one to every check below; application code may not land against it.
# ------------------------------------------------------------------
total_criteria = sum(len(tg.get("criteria", [])) for tg in data.get("taskGroups", []))
if total_criteria == 0 and not tg_filter and not file_mode:
    prefixes = app_prefixes
    app_touched = [f for f in changed
                   if any(f.startswith(p) or ("/" + p) in ("/" + f) for p in prefixes)
                   and not TEST_PATH.search(f)]
    if diff_source == "none":
        exemptions.append(("-", "no-task-groups", "[SKIPPED] vacuous-gate guard needs git to see the diff - "
                           "verify-results.json has zero criteria and that could not be checked against the change set"))
    elif app_touched:
        ex = data.get("noTaskGroupsExemption") or {}
        gate = (ex.get("gate") or "").strip(); note = (ex.get("note") or "").strip(); rb = (ex.get("reviewBy") or "").strip()
        ok = gate == EXEMPTION_TOKEN and note and rb
        expired = False
        if ok:
            try:
                expired = date.fromisoformat(rb) < date.today()
            except ValueError:
                ok = False
        if ok and not expired:
            exemptions.append(("-", "no-task-groups", f"[{EXEMPTION_TOKEN}] {note} (reviewBy {rb}; "
                               f"{len(app_touched)} application-code file(s) in this change set)"))
        elif ok and expired:
            fail("-", "no-task-groups",
                 f"noTaskGroupsExemption passed its reviewBy date ({rb}) while {len(app_touched)} application-code "
                 f"file(s) are in the change set (e.g. '{app_touched[0]}'). Add the active spec's task group and "
                 "criteria FAIL-first, or re-decide the exemption with a new reviewBy date.")
        else:
            fail("-", "no-task-groups",
                 f"{len(app_touched)} application-code file(s) in this change set (e.g. '{app_touched[0]}', "
                 f"source: {diff_source}) but verify-results.json has ZERO recorded criteria. Core Doctrine #1 and "
                 "#16: a spec and its task group land in verify-results.json BEFORE implementation touches "
                 "application code. Add the task group and criteria now (scripts/new-task-group.sh, "
                 "scripts/add-criteria.sh), or - for a genuinely spec-less scaffold commit - set top-level "
                 '"noTaskGroupsExemption": {"gate": "BOOTSTRAP", "note": "<reason>", "reviewBy": "YYYY-MM-DD"}.')

for tg in data.get("taskGroups", []):
    tg_id = tg.get("id", "?")
    if tg_filter and tg_id != tg_filter:
        continue
    started = parse_ts(tg.get("startedAt"))
    crits = tg.get("criteria", [])
    pass_crits = [c for c in crits if c.get("status") == "PASS"]
    # v3.3.0 [CHECKS]: a group with criteria and no FAIL row is a completion claim; the declared
    # checks must be PASS at HEAD. Groups still carrying FAIL rows are silent (work in progress).
    closed = bool(crits) and not any(c.get("status") == "FAIL" for c in crits)
    if closed and pass_crits and not file_mode:
        for prob in checks_problems():
            fail(tg_id, "-", f"[CHECKS] {prob}")
        if not DECLARED_CHECKS and not _no_checks_said:
            _no_checks_said = True
            exemptions.append(("-", "checks", "[NO-CHECKS] no checks declared in _docs/ai/verify/checks.env - a close relies on evidence files alone (declare TEST/BUILD/LINT there; scripts/check.sh --list)"))
        # v3.3.0 [RISK]: a high-risk group's completion claim carries a security review record
        # (the risk tier decides the loop shape; the gate sees the artefact, not the intention).
        if (tg.get("risk") or "medium") == "high":
            logs_dir_ = os.path.join(project_root, "_docs", "ai", "logs")
            st = parse_ts(tg.get("startedAt"))
            st_epoch = st.timestamp() if st else 0
            have = False
            try:
                for f in os.listdir(logs_dir_):
                    if f.endswith("_security-report.md") and os.path.getmtime(os.path.join(logs_dir_, f)) >= st_epoch and os.path.getsize(os.path.join(logs_dir_, f)) > 0:
                        have = True; break
            except OSError:
                pass
            if not have:
                fail(tg_id, "-", "[RISK] high-risk task group closed with no *_security-report.md in _docs/ai/logs/ written since it opened (security-reviewer pass, Core Doctrine #7)")
    # v3.3.0 [TEST-MODIFIED]: tests present at the red-baseline commit are protected from the
    # implementer; a modification or deletion since needs a recorded allowance.
    rb_val = tg.get("redBaseline")
    if pass_crits and is_git and isinstance(rb_val, str) and rb_val.strip():
        rb_sha = git_first_commit_sha(os.path.join("_docs", "ai", "verify", "evidence", rb_val.strip()).replace("\\", "/"))
        if rb_sha:
            touched = git_test_files_changed_since(rb_sha)
            allow = (tg.get("allowTestChange") or "").strip()
            if touched and not allow:
                fail(tg_id, "-", "[TEST-MODIFIED] test file(s) from the red baseline modified or deleted since it was committed: "
                     + ", ".join(touched[:5]) + (" ..." if len(touched) > 5 else "")
                     + " - the implementer never modifies tests (Core Doctrine #3); record a spec-mandated change with "
                       "scripts/set-criterion.sh <TG> --allow-test-change \"<brief reference>\"")
            elif touched and allow:
                exemptions.append((tg_id, "-", f"[TEST-CHANGE-ALLOWED] {allow} ({len(touched)} test file(s) changed since the red baseline)"))
    # v3.0.0: startedAt is the anchor for every ordering check; a missing one used to pass silently.
    if pass_crits and started is None:
        fail(tg_id, "-", "task group has PASS criteria but no parseable 'startedAt' (ISO-8601) - the red-baseline "
             "and evidence-freshness checks cannot run without it (new-task-group.sh writes it)")
    # v1.10.0 (findings 3.3 / CONSTITUTION #24): a "ui": true task group may not pass on
    # static evidence alone - once any criterion is PASS, at least one PASS criterion in the
    # group must carry a scripted interaction-test artefact (*.uatresults.txt).
    if tg.get("ui") is True:
        if pass_crits and not any(
            UAT.search(ev) for c in pass_crits for ev in (c.get("evidence") or [])
        ):
            fail(tg_id, "-", "ui-flagged task group has PASS criteria but no *.uatresults.txt "
                 "interaction-test evidence (screenshots alone are insufficient for UI behaviour)")
        # v3.0.0 (harvest 2026-09: five production defects behind 2,593 green tests): a ui group
        # also needs at least one capture from a DEPLOYED environment (".live." in the filename),
        # unless the group carries a criterion BLOCKED on DEPLOY (not yet deployable - sub-scoped).
        deploy_blocked = any(c.get("status") == "BLOCKED" and (c.get("gate") or "").strip() == "DEPLOY" for c in crits)
        if pass_crits and not deploy_blocked and not any(
            LIVE.search(ev) for c in pass_crits for ev in (c.get("evidence") or [])
        ):
            fail(tg_id, "-", "ui-flagged task group has PASS criteria but no deployed-environment capture "
                 "(name one evidence file <ID>.live.<png|http.txt|log>, or BLOCK a sub-scoped criterion on DEPLOY)")
    # v1.11.0 (Rec 1 / CONSTITUTION #26): once any criterion is PASS, the group must have a
    # recorded red baseline (failing-test evidence predating the first green evidence) or a
    # loud exemption. Red-before-green is proven by mtime ordering locally and, v3.0.0, by
    # COMMIT ordering where git knows both files.
    if pass_crits:
        rb = tg.get("redBaseline", None)
        if isinstance(rb, dict) and (rb.get("exempt") or "").strip():
            exemptions.append((tg_id, "redBaseline", f"[RED-EXEMPT] {rb['exempt'].strip()}"))
        elif isinstance(rb, str) and rb.strip():
            rb_path = contained(rb)
            if rb_path is None:
                fail(tg_id, "redBaseline", f"red baseline '{rb}' is not a plain name inside _docs/ai/verify/evidence/ (absolute, '..' or outside the evidence root)")
            elif not os.path.isfile(rb_path) or os.path.getsize(rb_path) == 0:
                fail(tg_id, "redBaseline", f"red baseline '{rb}' missing or empty")
            else:
                green_rel = [ev for c in pass_crits for ev in (c.get("evidence") or [])
                             if os.path.isfile(os.path.join(evidence_dir, ev))]
                # commit-order check (git-aware; works in CI and locally)
                rb_rel = os.path.relpath(rb_path, project_root).replace("\\", "/")
                rb_commit = git_first_commit_epoch(rb_rel)
                green_commits = [git_first_commit_epoch(os.path.relpath(os.path.join(evidence_dir, ev), project_root).replace("\\", "/"))
                                 for ev in green_rel]
                known_greens = [g for g in green_commits if g is not None]
                if rb_commit is not None and known_greens:
                    if rb_commit > min(known_greens):
                        fail(tg_id, "redBaseline",
                             "red baseline was committed AFTER the earliest PASS evidence (commit order) - "
                             "red is committed on its own before green (gate-sequence, VERIFY step)")
                elif is_git and rb_commit is None and green_rel and not known_greens:
                    exemptions.append((tg_id, "redBaseline",
                                       "[RED-ORDER-UNVERIFIABLE] red baseline and PASS evidence are uncommitted together - "
                                       "commit the red run on its own first so the ordering is provable"))
                if IN_CI:
                    if rb_commit is None:
                        exemptions.append((tg_id, "redBaseline",
                                           "[CI] red baseline not yet committed; mtime ordering not checkable in a fresh checkout"))
                else:
                    rb_m = os.path.getmtime(rb_path)
                    if started is not None:
                        rb_dt = datetime.fromtimestamp(rb_m, tz=timezone.utc)
                        st = started if started.tzinfo else started.replace(tzinfo=timezone.utc)
                        if rb_dt < st:
                            fail(tg_id, "redBaseline", f"red baseline '{rb}' predates task group start")
                    greens = [os.path.getmtime(os.path.join(evidence_dir, ev)) for ev in green_rel]
                    if greens and rb_m >= min(greens):
                        fail(tg_id, "redBaseline",
                             "red baseline does not predate the earliest PASS evidence "
                             "(red must be recorded BEFORE implementation goes green)")
        else:
            fail(tg_id, "redBaseline",
                 "task group has PASS criteria but no red baseline (record the failing-test "
                 "run as evidence/<TG>.red.testresults.txt, or set redBaseline to "
                 '{"exempt": "<reason>"} for groups with no meaningful red phase)')
    for crit in crits:
        cid = crit.get("id", "?")
        status = crit.get("status")

        if status not in ("PASS", "FAIL", "BLOCKED"):
            fail(tg_id, cid, f"illegal status '{status}' (only PASS, FAIL, BLOCKED exist)")
            continue

        # v3.0.0 (harvest 2026-09, recurred twice in one session): a spec addendum that
        # redefines a criterion must travel with a change to the tree's tests. Warning class.
        add_at = (crit.get("addendumAt") or "").strip()
        if add_at:
            try:
                date.fromisoformat(add_at[:10])
                changed_tests = git_test_change_since(add_at[:10])
                if changed_tests is False:
                    exemptions.append((tg_id, cid, f"[ADDENDUM-UNAPPLIED] criterion cites an addendum dated {add_at[:10]} "
                                       "but no test-path file has changed since - a ruling in the spec is not a fix to the tree"))
            except ValueError:
                fail(tg_id, cid, f"addendumAt '{add_at}' is not an ISO date")

        if status == "FAIL":
            continue

        if status == "BLOCKED":
            disposition = (crit.get("disposition") or "").strip()
            gate = (crit.get("gate") or "").strip()
            if not disposition:
                fail(tg_id, cid, "BLOCKED without a disposition (state the agreed reason and plan)")
                continue
            # v1.10.0 (findings 6.2 / CONSTITUTION #10): every BLOCKED names its gate from a
            # closed set so blocked reasons cannot be vague. PHASE-N-ENTRY takes a real number.
            if not (gate in GATE_TOKENS or re.fullmatch(r"PHASE-\d+-ENTRY", gate)):
                fail(tg_id, cid, f"BLOCKED with unrecognised gate '{gate or '(missing)'}' "
                     f"(allowed: EXTERNAL-SERVICE, DEPLOY, LABELLED-DATA, SIGN-OFF, PHASE-<n>-ENTRY)")
                continue
            blocked.append((tg_id, cid, f"[{gate}] {disposition}"))
            continue

        # status == PASS: evidence is mandatory
        evidence = crit.get("evidence") or []
        if not evidence:
            fail(tg_id, cid, "PASS with no evidence")
            continue
        for ev in evidence:
            if not ALLOWED.search(ev):
                fail(tg_id, cid, f"evidence '{ev}' does not match allowed patterns ({ALLOWED_DESC})")
                continue
            ev_path = contained(ev)
            if ev_path is None:
                fail(tg_id, cid, f"evidence '{ev}' is not a plain name inside _docs/ai/verify/evidence/ (absolute, '..' or outside the evidence root)")
                continue
            if not os.path.isfile(ev_path) or os.path.getsize(ev_path) == 0:
                fail(tg_id, cid, f"evidence '{ev}' missing or empty at {ev_path}")
                continue
            # v1.11.2 (re-review H7): same root cause as the red-baseline ordering - git drops
            # mtimes, so freshness is only checkable where files were written in place.
            if started is not None and not IN_CI:
                mtime = datetime.fromtimestamp(os.path.getmtime(ev_path), tz=timezone.utc)
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                if mtime < started:
                    fail(tg_id, cid, f"evidence '{ev}' predates task group start ({tg.get('startedAt')})")
        # v3.2.0 (spec kit): a criterion generated from a phase spec carries the evidence CLASS
        # the register fixed for it. A PASS must hold at least one file of each named class -
        # the pattern check above says the file is an allowed kind, this says it is the kind the
        # requirement was signed against (a tile-render capture is not proof of an admin form).
        classes = crit.get("evidenceClass") or []
        if isinstance(classes, list) and classes:
            for klass in classes:
                k = str(klass).strip().lower()
                if not any(EVIDENCE_CLASS_MATCH.get(k, lambda n: False)(e) for e in evidence):
                    fail(tg_id, cid, f"[EVIDENCE-CLASS] PASS holds no '{k}' evidence "
                         f"({EVIDENCE_CLASS_DESC.get(k, 'unknown class')}); the register fixed this class for the criterion - "
                         "capture it, or change the class by addendum")

# v1.11.0 (Rec 3/B4): if sub-agent reports exist for a task group with PASS criteria, the
# reasoned delegation log must exist and be non-empty (existence check; the evaluator does the
# substance cross-check against the machine ledger).
logs_dir = os.path.join(os.path.dirname(os.path.dirname(evidence_dir)), "logs")
try:
    has_reports = any(f.endswith(("_impl-report.md", "_test-report.md", "_security-report.md"))
                      for f in os.listdir(logs_dir))
    has_delegation = any(f.endswith("_delegation.md") and
                         os.path.getsize(os.path.join(logs_dir, f)) > 0
                         for f in os.listdir(logs_dir))
    any_pass = any(c.get("status") == "PASS" for tg in data.get("taskGroups", [])
                   for c in tg.get("criteria", []))
    if any_pass and has_reports and not has_delegation:
        fail("-", "delegation-log", "sub-agent reports exist but no non-empty *_delegation.md "
             "reasoned log (delegation-routing Step 7; the ledger hook captures facts, "
             "the reasoned log captures why)")
except OSError:
    pass

# v3.2.0 (spec kit): every contract criterion must be named in the spec or in an addendum file
# under _docs/ai/specs/. The register of addenda is the anti-drift mechanism; a criterion that
# appears in neither was born in a build session and never recorded. A note, not a failure:
# it stays visible at every gate run until scripts/new-addendum.sh registers the ID.
try:
    specs_dir = os.path.join(project_root, "_docs", "ai", "specs")
    spec_text = ""
    for root_, _dirs, files_ in os.walk(specs_dir):
        for f in files_:
            if f.endswith(".md"):
                try:
                    with open(os.path.join(root_, f), encoding="utf-8", errors="replace") as fh:
                        spec_text += fh.read() + "\n"
                except OSError:
                    pass
    if spec_text.strip():
        for tg in data.get("taskGroups", []):
            if tg_filter and tg.get("id") != tg_filter:
                continue
            for c in tg.get("criteria", []):
                cid_ = (c.get("id") or "").strip()
                if cid_ and cid_ not in spec_text:
                    exemptions.append((tg.get("id", "-"), cid_, "[UNREGISTERED-CRITERION] named in no spec or addendum under _docs/ai/specs/ - register it with scripts/new-addendum.sh"))
except OSError:
    pass

# Exemptions are the loud part of the contract: always printed.
for tg_id, cid, text in exemptions:
    print(f"GATE NOTE [{tg_id}/{cid}]: {text}", file=sys.stderr)
# BLOCKED rows are listed only on request (v3.0.0 quiet default) - the summary counts them.
if verbose:
    for tg_id, cid, disposition in blocked:
        print(f"GATE NOTE [{tg_id}/{cid}]: BLOCKED - {disposition}", file=sys.stderr)

if failures:
    print(f"verify-gate: {failures} violation(s). No completion claim may be made.", file=sys.stderr)
    sys.exit(1)

scope = f"task group {tg_filter}" if tg_filter else "all task groups"
n_groups = len(data.get("taskGroups", [])) if not tg_filter else 1
suffix = f"; {len(blocked)} BLOCKED with disposition" + ("" if verbose or not blocked else " (--verbose lists them)") if blocked else ""
print(f"verify-gate: PASS ({scope}: {n_groups} group(s), {total_criteria} criteria{suffix})")
PYEOF
