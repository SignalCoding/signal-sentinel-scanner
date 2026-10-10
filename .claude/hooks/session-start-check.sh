#!/usr/bin/env bash
# SessionStart hook (CC edition, v1.8.1-cc; v1.10 EOL check; v1.11 gate-state announce;
# v3.0.0 seed/origin/models/apparatus checks) - injects completion-contract state at session start.
# Output on stdout is added to Claude's context (SessionStart semantics).
P="${CLAUDE_PROJECT_DIR:-$(pwd)}"
CFG_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
echo "== Framework session start (AI Agent Master Library, Claude Code edition) =="
[[ -f "$P/CONSTITUTION.md" ]] && echo "CONSTITUTION.md present - it always applies (imported via CLAUDE.md)."

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
  echo "ATTENTION: Python 3 not found on PATH. The evidence gate (verify-gate.sh) and its hooks"
  echo "cannot run without it - install Python before any feature work or completion claims."
fi

if [[ -f "$P/_docs/ai/verify/verify-results.json" ]]; then
  if [[ -n "$PY" ]]; then
    COUNTS=$(pyc -c '
import json,sys,os
try:
    d=json.load(open(sys.argv[1],encoding="utf-8"))
    groups=d.get("taskGroups",[])
    crits=[c for tg in groups for c in tg.get("criteria",[])]
    f=sum(1 for c in crits if c.get("status")=="FAIL")
    b=sum(1 for c in crits if c.get("status")=="BLOCKED")
    print(f"{f} criteria currently FAIL, {b} BLOCKED ({len(groups)} task group(s), {len(crits)} criteria)")
    # v3.0.0 seed detection: zero criteria but application code on disk = the vacuous gate.
    if not crits:
        root=sys.argv[2]
        app=[d_ for d_ in ("src","app","lib","components","pages","api","services","android","ios") if os.path.isdir(os.path.join(root,d_)) and any(os.scandir(os.path.join(root,d_)))]
        ex=d.get("noTaskGroupsExemption") or {}
        if app and not ex:
            print("ATTENTION: the completion contract has ZERO criteria but application code exists in "+", ".join(app)+"/ - the gate is vacuous (Core Doctrine #16). Record the active spec: scripts/new-task-group.sh + scripts/add-criteria.sh BEFORE any further implementation.")
        elif app and ex:
            print("NOTE: zero criteria; noTaskGroupsExemption active (%s, reviewBy %s)." % (ex.get("gate","?"), ex.get("reviewBy","?")))
except Exception:
    print("? (verify-results.json unreadable)")
' "$P/_docs/ai/verify/verify-results.json" "$P" 2>/dev/null || echo "?")
    echo "Completion contract active: ${COUNTS%%$'\n'*} (default-FAIL is correct until evidenced)."
    [[ "$COUNTS" == *$'\n'* ]] && echo "${COUNTS#*$'\n'}"
  fi
else
  echo "NOTE: completion contract not adopted - verify-results.json missing (bootstrap seeds it with a BOOTSTRAP exemption; scripts/new-task-group.sh creates it on first use)."
fi
# v2.6.0 (FortisISO field harvest #1): conflict-file AGE escalation. A 10-day-old unresolved
# conflict left a live project running with the modern enforcement layer installed on disk
# but invisible to the session (stale manual never mentioned it). "Present five minutes" and
# "present ten days" must not look identical.
CONFLICT_FILE="$P/_docs/ai/_bootstrap-conflicts.md"
if [[ -f "$CONFLICT_FILE" ]]; then
  CGEN="$(sed -n 's/^\*\*Generated:\*\* //p' "$CONFLICT_FILE" | head -1)"
  CAGE=""
  # v3.0.1: Python first (already resolved), then GNU date, then BSD date -j - on macOS the
  # GNU-only `date -d` silently produced no age, so the escalation never fired.
  if [[ -n "$CGEN" ]]; then
    CGEN_S=""
    if [[ -n "$PY" ]]; then
      CGEN_S="$(CG="$CGEN" pyc -c 'import os,datetime; t=os.environ["CG"].strip().replace("Z","+00:00"); d=datetime.datetime.fromisoformat(t); d=d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc); print(int(d.timestamp()))' 2>/dev/null || true)"
    fi
    [[ -n "$CGEN_S" ]] || CGEN_S="$(date -d "$CGEN" +%s 2>/dev/null || date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$CGEN" +%s 2>/dev/null || true)"
    [[ -n "$CGEN_S" ]] && CAGE=$(( ( $(date +%s) - CGEN_S ) / 86400 ))
  fi
  if [[ -n "$CAGE" && "$CAGE" -gt 3 ]]; then
    echo "=================================================================="
    echo "ATTENTION - BLOCKER-CLASS: _bootstrap-conflicts.md has been open for $CAGE DAYS."
    echo "Unresolved conflicts mean this project may be running a STALE manual while newer"
    echo "enforcement machinery sits installed but invisible (the FortisISO incident)."
    echo "Resolve the conflict table BEFORE any other work."
    echo "=================================================================="
  else
    echo "ATTENTION: _bootstrap-conflicts.md exists${CAGE:+ (age: $CAGE day(s))} - resolve before other work."
  fi
fi

# v2.6.0 (same harvest): stale-manual heuristic, independent of the conflict file surviving.
# If the project's delivered-library stamp is v2.3+ (doctrine-block era) but the manual being
# read lacks the Core Doctrine block, the manual predates the installed apparatus - the exact
# silent capability mismatch. Mechanical, grep-able, no memory required.
# v3.0.0: the marker is CORE-DOCTRINE:BEGIN (CLAUDE.md only; AGENTS.md is a pointer stub).
_STALE_STAMP="$P/_docs/ai/.aiagent-library-version"
if [[ -f "$_STALE_STAMP" ]]; then
  _plv="$(cat "$_STALE_STAMP" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$(printf '%s\n%s\n' "2.3.0" "$_plv" | sort -V | head -1)" == "2.3.0" ]]; then
    if [[ -f "$P/CLAUDE.md" ]] && ! grep -q "CORE-DOCTRINE:BEGIN" "$P/CLAUDE.md"; then
      if grep -q "PARITY:BEG""IN" "$P/CLAUDE.md"; then
        echo "ATTENTION: CLAUDE.md carries the v2.x PARITY block, not the v3 Core Doctrine block - the"
        echo "manual predates the installed apparatus. Re-run bootstrap (it merges, reporting conflicts)"
        echo "or apply the MIGRATION.md v2.x -> v3.0.0 recipe before trusting this session's process."
      else
        echo "ATTENTION: CLAUDE.md predates the delivered library apparatus (v$_plv is installed but"
        echo "this manual lacks the Core Doctrine block). The session is being steered by a STALE"
        echo "manual - merge the template manual (see _bootstrap-conflicts.md or re-run bootstrap)."
      fi
    fi
  fi
fi

# v3.0.0: retired-apparatus sweep - names that no longer exist anywhere in the library. A
# project manual that still mentions them is steering sessions toward machinery that is gone.
# (pattern assembled from pieces so the library's own retired-name sweep does not match this file)
_RD="dro""id"; _FY="fac""tory"
_RETIRED="${_FY}-${_RD}|${_RD} exec|sync-${_RD}|~/\.${_FY}|PARITY:BEG""IN|claude-opus-4""-8|coding-agent-op""us|coding-agent-che""ap|test-writer-op""us|test-writer-che""ap|security-reviewer-op""us"
_HITS="$(grep -rlE "$_RETIRED" "$P/CLAUDE.md" "$P/AGENTS.md" "$P/.claude/agents" "$P/.claude/rules" "$P/_docs/ai/configuration.md" "$P/_docs/ai/models.env" 2>/dev/null | sed "s|^$P/||" | tr '\n' ' ')"
if [[ -n "$_HITS" ]]; then
  echo "ATTENTION: retired apparatus referenced in: ${_HITS}- (the second-tool adapter, the PARITY block"
  echo "and the 4.x evaluator model pin were removed in library v3.0.0). Follow MIGRATION.md; a retired"
  echo "model ID makes run-evaluator.sh fail before any verdict is written."
fi

# v3.0.0: evaluator model pin - models.env is the single source; the ID must be one the installed
# capability matrix knows, or the evaluator fails at the CLI with nothing on disk.
MODELS_ENV="$P/_docs/ai/models.env"
MATRIX="$CFG_DIR/skills/delegation-routing/references/model-capability-matrix.md"
if [[ -f "$MODELS_ENV" ]]; then
  _EM="$(sed -n 's/^EVALUATOR_MODEL=//p' "$MODELS_ENV" | head -1 | tr -d '"'"'"'[:space:]')"
  if [[ -z "$_EM" ]]; then
    echo "ATTENTION: _docs/ai/models.env has no EVALUATOR_MODEL - the evaluator is unpinned; set it."
  elif [[ "$_EM" =~ ^(opus|sonnet|haiku|fable)$ ]]; then
    echo "Models: evaluator on the '$_EM' family (_docs/ai/models.env; the verdict header records the resolved ID)."
  elif [[ -f "$MATRIX" ]] && ! grep -qF "$_EM" "$MATRIX"; then
    echo "ATTENTION: EVALUATOR_MODEL=$_EM (models.env) is not a family alias (opus/sonnet/haiku/fable) and is"
    echo "not in the installed model-capability matrix - retired or mistyped. Prefer the alias."
  else
    echo "Models: evaluator pinned to $_EM (_docs/ai/models.env; a family alias would follow new iterations automatically)."
  fi
  # v3.3.0: the compat probe is the truth about what the installed CLI accepts (aliases, flags, hook
  # `if`, structured output); a missing or stale probe is announced, never assumed.
  _CCV="$(claude --version </dev/null 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  if [[ -n "$_CCV" ]]; then
    if [[ -f "$CFG_DIR/.aiagent-compat-$_CCV.json" ]]; then
      grep -q '"ok": true' "$CFG_DIR/.aiagent-compat-$_CCV.json" 2>/dev/null \
        && echo "Compat: claude $_CCV probed ($CFG_DIR/.aiagent-compat-$_CCV.json)." \
        || echo "ATTENTION: compat probe for claude $_CCV recorded failures - read $CFG_DIR/.aiagent-compat-$_CCV.json (scripts/compat-check.sh in the library)."
    else
      echo "NOTE: claude $_CCV has not been probed on this machine - run bash <library>/scripts/compat-check.sh once (aliases, --restricted, hook if-filters, structured output)."
    fi
  fi
else
  echo "NOTE: _docs/ai/models.env missing - evaluator model falls back to the agent frontmatter; run scripts/bootstrap.sh --refresh-hooks from the library to stamp it."
fi

# v1.11.0 (Rec 2): announce gate state; warn when configuration changed after gates were run.
# v3.0.0: the configuration.md timestamp is its last COMMIT time when git knows it unmodified
# (a fresh clone stamps every file's mtime with checkout time, which made every clone report
# stale gates); mtime is used only for an untracked or locally modified file.
GS="$P/_docs/ai/verify/gate-state.json"
if [[ -f "$GS" && -n "$PY" ]]; then
  CFG_TS=""
  if git -C "$P" ls-files --error-unmatch _docs/ai/configuration.md >/dev/null 2>&1 && git -C "$P" diff --quiet -- _docs/ai/configuration.md 2>/dev/null; then
    CFG_TS="$(git -C "$P" log -1 --format=%ct -- _docs/ai/configuration.md 2>/dev/null || true)"
  fi
  CFG_TS_VAL="$CFG_TS" "$PY" "${PY_ARGS[@]}" - "$GS" "$P/_docs/ai/configuration.md" <<'GEOF'
import json, os, sys, datetime
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    gates = {str(g.get("id")): g for g in data.get("gates", [])}
    n_pass = sum(1 for g in gates.values() if g.get("status") == "PASS")
    g8 = gates.get("8", {}).get("status", "absent")
    blocked = "" if g8 in ("PASS", "EXEMPT") else " - task-group creation BLOCKED until Gate 8 signs off"
    print(f"Gates: {n_pass}/{len(gates)} PASS; Gate 8: {g8}{blocked}.")
    if "0.5" not in gates:
        print("  NOTE: Gate 0.5 (Repository standards) not recorded - add it from gate-state.example.json (v3.0.0).")
    today = datetime.date.today()
    for gid, g in gates.items():
        if g.get("status") == "EXEMPT":
            rb = (g.get("reviewBy") or "").strip()
            late = ""
            try:
                if rb and datetime.date.fromisoformat(rb) < today: late = f" - PAST reviewBy {rb}, re-decide"
            except ValueError:
                pass
            print(f"  NOTE: gate {gid} EXEMPT - {g.get('note','')}{late}")
    try:
        cfg_ts = os.environ.get("CFG_TS_VAL", "").strip()
        cfg_m = float(cfg_ts) if cfg_ts else os.path.getmtime(sys.argv[2])
        ts = [g.get("timestamp", "") for g in gates.values() if g.get("timestamp")]
        newest = max((datetime.datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp() for t in ts), default=0)
        if newest and cfg_m > newest:
            print("ATTENTION: configuration.md is NEWER than the recorded gate state - gate state is")
            print("stale; re-run the gate sequence from Gate 0 (skills/gate-sequence).")
    except (OSError, ValueError):
        pass
except Exception:
    print("Gates: gate-state.json unreadable - validate with scripts/verify-gate.sh --gates.")
GEOF
elif [[ ! -f "$GS" ]]; then
  echo "NOTE: gate-state.json missing - the gate sequence has not been recorded; task-group"
  echo "creation will refuse until Gate 8 is PASS (see gate-state.example.json)."
fi

# v3.0.0 (repo standards as the norm): the remote is part of the definition of done. No
# upstream, or work sitting unpushed for more than a day, is announced every session.
if git -C "$P" rev-parse --git-dir >/dev/null 2>&1; then
  if ! git -C "$P" remote get-url origin >/dev/null 2>&1; then
    echo "ATTENTION: no 'origin' remote - Gate 0.5 (repo standards) is not met: create the GitHub repo,"
    echo "protect main, enable secret scanning, push, and confirm CI is green (skills/repo-standards, Phase 0-1)."
  elif ! git -C "$P" rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
    echo "ATTENTION: current branch has no upstream - push it (git push -u origin <branch>) before feature work; unpushed work is uninsured work."
  else
    AHEAD="$(git -C "$P" rev-list --count '@{u}..HEAD' 2>/dev/null || echo 0)"
    if [[ "$AHEAD" -gt 0 ]]; then
      OLDEST="$(git -C "$P" log --reverse --format=%ct '@{u}..HEAD' 2>/dev/null | head -1)"
      AGE_H=$(( ( $(date +%s) - ${OLDEST:-$(date +%s)} ) / 3600 ))
      if [[ "$AGE_H" -ge 24 ]]; then
        echo "ATTENTION: $AHEAD unpushed commit(s), oldest ~$(( AGE_H / 24 )) day(s) old - push cadence rule: every task-group close and every session end pushes."
      else
        echo "Remote: $AHEAD unpushed commit(s) (push at task-group close / session end)."
      fi
    fi
  fi
fi

# v2.0.0 (meta-lesson 6): install-state verification - repo-clean is not runtime-correct.
# v3.0.0: the reverse mismatch is announced too (installed library NEWER than the project's
# delivered apparatus = hooks/scripts/manual predate the library; refresh them).
PROJ_LIBVER_FILE="$P/_docs/ai/.aiagent-library-version"
INSTALLED_LIBVER_FILE="$CFG_DIR/.aiagent-library-version"
if [[ -f "$PROJ_LIBVER_FILE" ]]; then
  PROJ_LV="$(cat "$PROJ_LIBVER_FILE" 2>/dev/null | tr -d '[:space:]')"
  if [[ ! -f "$INSTALLED_LIBVER_FILE" ]]; then
    echo "ATTENTION: no installed-library version stamp in the Claude config dir - the machine's synced copy"
    echo "predates v2.0.0 or sync has never run. Run adapters/claude-code/sync-claude.sh from the"
    echo "library (project expects >= $PROJ_LV)."
  else
    INST_LV="$(cat "$INSTALLED_LIBVER_FILE" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$(printf '%s\n%s\n' "$PROJ_LV" "$INST_LV" | sort -V | tail -1)" != "$INST_LV" ]]; then
      echo "ATTENTION: installed library ($INST_LV) is OLDER than this project's library ($PROJ_LV)."
      echo "Sessions are running stale governance - re-run sync-claude.sh before feature work."
    elif [[ "${PROJ_LV%%.*}" != "${INST_LV%%.*}" || "${PROJ_LV#*.}" != "${INST_LV#*.}" ]]; then
      echo "ATTENTION: this project's delivered apparatus is v$PROJ_LV but the installed library is v$INST_LV -"
      echo "hooks, scripts and the manual predate the library. From the library: scripts/bootstrap.sh <project> --refresh-hooks (see MIGRATION.md)."
    fi
  fi
fi
# v3.0.0: delivered-apparatus integrity - hooks and scripts edited in place drift silently.
HASHES="$P/_docs/ai/.aiagent-apparatus.sha256"
# v3.0.1: sha256sum (GNU) or shasum -a 256 (macOS) - the drift check used to be skipped silently on Macs
SHA256_CHECK=""
if printf x | sha256sum >/dev/null 2>&1; then SHA256_CHECK="sha256sum -c --quiet"; elif printf x | shasum -a 256 >/dev/null 2>&1; then SHA256_CHECK="shasum -a 256 -c --quiet"; fi
if [[ -f "$HASHES" && -n "$SHA256_CHECK" ]]; then
  DRIFT="$(cd "$P" && $SHA256_CHECK "$HASHES" 2>/dev/null | sed 's/: FAILED.*//' | tr '\n' ' ')"
  [[ -n "$DRIFT" ]] && echo "NOTE: delivered hook/script file(s) modified since bootstrap: ${DRIFT}- intended? (bootstrap --refresh-hooks restores the library versions; local fixes belong in the library via a lessons record)."
fi

# v2.4.0 (spend/security corpus, double-sourced): agent ACTION VOLUME as a visible signal.
# A compromised agent ran 17,600 individually-plausible actions in 2.5 days (HF breach); a
# runaway model "explodes in an avalanche of unnecessary tool calls" (cost face, same
# counter). tool-audit.log records every allowed call but nothing read it back - now the
# session announces the delta so an anomalous-volume session is at least VISIBLE.
AUDIT_LOG="$P/_docs/ai/logs/tool-audit.log"
AUDIT_MARK="$P/_docs/ai/logs/.tool-audit-last-count"
if [[ -f "$AUDIT_LOG" ]]; then
  AUD_NOW="$(wc -l < "$AUDIT_LOG" | tr -d '[:space:]')"
  AUD_PREV="$(cat "$AUDIT_MARK" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$AUD_PREV" =~ ^[0-9]+$ ]]; then
    echo "tool-audit: $AUD_NOW logged calls (+$(( AUD_NOW - AUD_PREV )) since last session start)."
  else
    echo "tool-audit: $AUD_NOW logged calls (first count - delta reporting starts next session)."
  fi
  printf '%s\n' "$AUD_NOW" > "$AUDIT_MARK" 2>/dev/null || true
fi

# manual size is a per-session cost (~290 tokens per KB, re-sent every turn and re-paid by every
# sub-agent). The library's manuals ship under 14 KB / 150 lines; announce when a project's
# CLAUDE.md passes 16 KB so history stops accumulating in it (Core Doctrine #17).
if [[ -f "$P/CLAUDE.md" ]]; then
  _MSZ="$(wc -c < "$P/CLAUDE.md" | tr -d '[:space:]')"
  _MLN="$(wc -l < "$P/CLAUDE.md" | tr -d '[:space:]')"
  if [[ "$_MSZ" -gt 16384 || "$_MLN" -gt 200 ]]; then
    echo "NOTE: CLAUDE.md is $(( _MSZ / 1024 )) KB / ${_MLN} lines (library manuals ship under 14 KB / 150 lines; the tool's own guidance is under 200 lines). Every KB is paid on every turn and by every sub-agent. One statement, one home: a rule belongs in its owner file, history in _docs/ai/lessons/ and the decision log (Core Doctrine #17)."
  fi
fi

# v3.0.0: session-metrics kit (opt-in) - one line so its presence and cadence are visible.
if [[ -f "$P/_docs/ai/metrics/metrics.jsonl" ]]; then
  MSESS="$(grep -c '"event": *"SessionStart"' "$P/_docs/ai/metrics/metrics.jsonl" 2>/dev/null || echo 0)"
  echo "session-metrics: active ($MSESS session start(s) logged; report: bash scripts/metrics/metrics.sh report)."
fi

# v1.11.0 (FortisISO 2026-08-02 #2): COMPREHENSIVE/REGULATORY governance requires artefact
# logging; detect the silent-stop failure mode the skill itself predicts.
if [[ -f "$P/_docs/ai/configuration.md" && -d "$P/_docs/ai/logs" ]]; then
  if grep -qiE "governance.*(comprehensive|regulatory)" "$P/_docs/ai/configuration.md" 2>/dev/null; then
    # v3.0.1: no `find -printf` (GNU-only; BSD find silently produced nothing here)
    NEWEST_LOG=""
    if [[ -n "$PY" ]]; then
      NEWEST_LOG=$(LOGS="$P/_docs/ai/logs" pyc -c 'import os; r=os.environ["LOGS"]; m=[int(os.path.getmtime(os.path.join(d,f))) for d,_,fs in os.walk(r) for f in fs]; print(max(m) if m else "")' 2>/dev/null || true)
    fi
    NEWEST_COMMIT=$(git -C "$P" log -1 --format=%ct 2>/dev/null || echo 0)
    if [[ -n "$NEWEST_LOG" && "$NEWEST_COMMIT" -gt 0 ]]; then
      GAP_DAYS=$(( (NEWEST_COMMIT - NEWEST_LOG) / 86400 ))
      if [[ "$GAP_DAYS" -gt 7 ]]; then
        echo "ATTENTION: AI Governance is COMPREHENSIVE/REGULATORY but the newest _docs/ai/logs/"
        echo "artefact is ~${GAP_DAYS} days older than the newest commit. The artefact-logging"
        echo "obligation appears to have silently stopped (the exact failure mode"
        echo "ai-code-governance predicts). Log the missing spec/impl/security artefacts."
      fi
    fi
  fi
fi

# v1.10.0 (findings 4.4): warn when .editorconfig and .gitattributes both claim EOL authority -
# reconcile BEFORE the format gate produces a 30,000-violation storm.
if [[ -f "$P/.editorconfig" && -f "$P/.gitattributes" ]]; then
  if grep -qiE '^\s*(end_of_line|trim_trailing_whitespace)\s*=' "$P/.editorconfig" 2>/dev/null \
     && grep -qiE '(^|\s)(text=auto|eol=)' "$P/.gitattributes" 2>/dev/null; then
    echo "ATTENTION: .editorconfig sets end_of_line/trim_trailing_whitespace while .gitattributes"
    echo "manages EOL (text=auto/eol=). Two formatting authorities WILL conflict on a mixed-EOL"
    echo "tree. Remove the EOL settings from .editorconfig (line endings are git's job) before"
    echo "running any format gate - see your project's stack rules under .claude/rules/."
  fi
fi
exit 0
