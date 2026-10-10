#!/usr/bin/env bash
# archive-spec.sh (v2.3.0, ADR-2300) - archive a completed spec and merge its Capability
# Deltas into the living system spec (_docs/ai/SYSTEM-SPEC.md).
#
# Usage: bash scripts/archive-spec.sh _docs/ai/specs/<slug>.md
#
# Refuses unless the spec's task groups are gated: verify-gate.sh must exit 0 (the same
# evidence bar as any completion claim - archiving an ungated spec would merge unproven
# capabilities into the source of truth).
#
# Delta semantics (one row per line in the spec's "## Capability Deltas" table):
#   ADDED     <slug>  -> append row to SYSTEM-SPEC (refuses if slug already exists)
#   MODIFIED  <slug>  -> replace that slug's Statement (refuses if slug missing)
#   REMOVED   <slug>  -> delete that slug's row (refuses if slug missing)
#   UNCHANGED <slug>  -> no-op (declared refactor)
# Refusals are loud and nothing is written on any refusal - the merge is all-or-nothing.
#
# v3.0.0: (a) the archived spec's evidence moves with it - every evidence file referenced by the
# spec's task groups (plus their red baselines and verdicts) is moved to
# _docs/ai/completed/<slug>-evidence/ so the live evidence folder holds only live work (a
# 34-row project was carrying every log it had ever produced); the archived task groups are
# rewritten to point at the new location and REMOVED from verify-results.json's live list into
# _docs/ai/completed/<slug>-verify-results.json. (b) emits a TG-CLOSE session-metrics marker per
# archived task group when the kit is installed.
set -euo pipefail
die() { echo "archive-spec: FATAL: $*" >&2; exit 1; }

SPEC="${1:-}"
[[ -n "$SPEC" && -f "$SPEC" ]] || die "usage: archive-spec.sh _docs/ai/specs/<slug>.md (file must exist)"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
SYSSPEC="_docs/ai/SYSTEM-SPEC.md"
[[ -f "$SYSSPEC" ]] || die "$SYSSPEC missing - bootstrap delivers it; do not archive without the living spec present"
COMPLETED_DIR="_docs/ai/completed"
mkdir -p "$COMPLETED_DIR"
SLUG="$(basename "$SPEC" .md)"
[[ ! -f "$COMPLETED_DIR/$SLUG.md" ]] || die "$COMPLETED_DIR/$SLUG.md already exists"

# Gate: same bar as any completion claim.
bash scripts/verify-gate.sh || die "verify-gate FAILED - an ungated spec does not get archived (evidence before claims)"

# Extract delta rows: | ADDED | slug | statement |
DELTAS="$(awk '/^## Capability Deltas/{f=1;next} /^## /{f=0} f' "$SPEC" \
  | grep -E '^\|[[:space:]]*(ADDED|MODIFIED|REMOVED|UNCHANGED)[[:space:]]*\|' || true)"
[[ -n "$DELTAS" ]] || die "no Capability Deltas rows found in $SPEC (v2.3.0 spec contract: every spec declares its deltas; use one UNCHANGED row for pure refactors)"

TODAY="$(date +%Y-%m-%d)"
TMP="$(mktemp)"
cp "$SYSSPEC" "$TMP"

field() { echo "$1" | awk -F'|' -v n="$2" '{gsub(/^[ \t]+|[ \t]+$/,"",$n); print $n}'; }

while IFS= read -r row; do
  KIND="$(field "$row" 2)"; CAP="$(field "$row" 3)"; STMT="$(field "$row" 4)"
  [[ -n "$CAP" ]] || die "delta row with empty capability slug: $row"
  case "$KIND" in
    ADDED)
      grep -q "^| $CAP |" "$TMP" && die "ADDED $CAP but it already exists in $SYSSPEC (use MODIFIED)"
      printf '| %s | %s | %s | %s |\n' "$CAP" "$STMT" "$SLUG" "$TODAY" >> "$TMP" ;;
    MODIFIED)
      grep -q "^| $CAP |" "$TMP" || die "MODIFIED $CAP but it does not exist in $SYSSPEC (use ADDED)"
      # replace the whole row, preserving the slug column
      ESC_STMT="$(printf '%s' "$STMT" | sed 's/[&/\]/\\&/g')"
      sed -i.bak "s/^| $CAP |.*/| $CAP | $ESC_STMT | $SLUG | $TODAY |/" "$TMP" && rm -f "$TMP.bak" ;;   # -i.bak: BSD sed needs a suffix
    REMOVED)
      grep -q "^| $CAP |" "$TMP" || die "REMOVED $CAP but it does not exist in $SYSSPEC"
      sed -i.bak "/^| $CAP |/d" "$TMP" && rm -f "$TMP.bak" ;;
    UNCHANGED) : ;;
    *) die "unknown delta kind: $KIND" ;;
  esac
done <<< "$DELTAS"

mv "$TMP" "$SYSSPEC"
mv "$SPEC" "$COMPLETED_DIR/$SLUG.md"
echo "archive-spec: merged $(echo "$DELTAS" | wc -l | tr -d ' ') delta row(s) into $SYSSPEC; spec archived to $COMPLETED_DIR/$SLUG.md"

# ------------------------------------------------------------------
# v3.0.0: move this spec's task groups and their evidence out of the live contract.
# Task groups belong to the spec named in verify-results.json "spec" OR carry a "spec" field
# of their own; groups with neither are left in place (nothing is guessed).
# ------------------------------------------------------------------
RESULTS="_docs/ai/verify/verify-results.json"
if [[ -f "$RESULTS" ]]; then
  PY=""; PY_ARGS=()
  # Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
  pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
  for _c in python3 python py; do
    command -v "$_c" >/dev/null 2>&1 || continue
    [[ "$_c" == "py" ]] && _a=(-3) || _a=()
    if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
  done
  if [[ -n "$PY" ]]; then
    ARCHIVED_TGS="$(RESULTS_PATH="$RESULTS" SLUG_VAL="$SLUG" SPEC_BASENAME="$(basename "$SPEC")" COMPLETED_VAL="$COMPLETED_DIR" pyc - <<'PYEOF'
import json, os, shutil
path = os.environ["RESULTS_PATH"]; slug = os.environ["SLUG_VAL"]; spec_name = os.environ["SPEC_BASENAME"]
completed = os.environ["COMPLETED_VAL"]
data = json.load(open(path, encoding="utf-8"))
top_spec = os.path.basename((data.get("spec") or "").strip())
def belongs(tg):
    own = os.path.basename((tg.get("spec") or "").strip())
    if own: return own == spec_name
    return top_spec == spec_name
keep, gone = [], []
for tg in data.get("taskGroups", []):
    (gone if belongs(tg) else keep).append(tg)
if not gone:
    print(""); raise SystemExit(0)
evdir = "_docs/ai/verify/evidence"; vdir = "_docs/ai/verify/verdicts"
dest = os.path.join(completed, f"{slug}-evidence"); os.makedirs(dest, exist_ok=True)
moved = 0
def move(name):
    global moved
    src = os.path.join(evdir, name)
    if os.path.isfile(src):
        shutil.move(src, os.path.join(dest, os.path.basename(name))); moved += 1
for tg in gone:
    rb = tg.get("redBaseline")
    if isinstance(rb, str) and rb.strip(): move(rb.strip())
    for c in tg.get("criteria", []):
        for ev in c.get("evidence") or []: move(ev)
    if os.path.isdir(evdir):
        for n in list(os.listdir(evdir)):
            if n.startswith(tg.get("id","?") + ".") or n.startswith(tg.get("id","?") + "-"): move(n)
    if os.path.isdir(vdir):
        for n in list(os.listdir(vdir)):
            if n.startswith(tg.get("id","?") + "-verdict"):
                shutil.move(os.path.join(vdir, n), os.path.join(dest, n)); moved += 1
    tg["archivedTo"] = dest
with open(os.path.join(completed, f"{slug}-verify-results.json"), "w", encoding="utf-8") as fh:
    json.dump({"spec": spec_name, "archivedFrom": path, "taskGroups": gone}, fh, indent=2); fh.write("\n")
data["taskGroups"] = keep
if top_spec == spec_name: data["spec"] = ""
with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2); fh.write("\n")
print(" ".join(tg.get("id","?") for tg in gone) + f"|{moved}")
PYEOF
)"
    if [[ -n "$ARCHIVED_TGS" ]]; then
      TG_LIST="${ARCHIVED_TGS%|*}"; MOVED="${ARCHIVED_TGS##*|}"
      echo "archive-spec: task group(s) $TG_LIST moved to $COMPLETED_DIR/$SLUG-verify-results.json; $MOVED evidence/verdict file(s) to $COMPLETED_DIR/$SLUG-evidence/"
      if [[ -f scripts/metrics/hook.sh ]]; then
        for _tg in $TG_LIST; do bash scripts/metrics/hook.sh TGClose "$_tg" >/dev/null 2>&1 || true; done
      fi
    else
      echo "archive-spec: no task groups in verify-results.json belong to $(basename "$SPEC") (top-level \"spec\" or per-group \"spec\" field) - live contract left unchanged."
    fi
  fi
fi
echo "Commit the living spec, the archive and the evidence move together - they move as one change."
