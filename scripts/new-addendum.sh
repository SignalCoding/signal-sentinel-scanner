#!/usr/bin/env bash
# new-addendum.sh "<subject>" [--criteria "P1-XXX-C1,P1-YYY-C2"] [--by "<name>"] [--spec <slug>]
#
# Allocates the next addendum number from _docs/ai/specs/ADDENDA.md (the ONLY place numbers come
# from), creates _docs/ai/specs/<slug>.addendum-A<n>-<subject-kebab>.md from the spec kit's
# spec-addendum template with the number, date and subject filled in, and appends the register
# row. Nothing else is changed: the criteria themselves move through scripts/set-criterion.sh
# (--addendum <date> on each one) once the addendum is written and authorised.
#
# Why a script: numbering collided three times on one project before a register existed, and
# criteria born in build sessions went unregistered for weeks. The register row exists from the
# moment the file does, so the gate's [UNREGISTERED-CRITERION] note clears as soon as the file
# names the criterion.
set -euo pipefail

USAGE='Usage: new-addendum.sh "<subject>" [--criteria "ID,ID,..."] [--by "<name>"] [--spec <slug>]'
SUBJECT="${1:?$USAGE}"; shift
CRITERIA=""; BY=""; SLUG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --criteria) CRITERIA="${2:?}"; shift ;;
    --by) BY="${2:?}"; shift ;;
    --spec) SLUG="${2:?}"; shift ;;
    *) echo "$USAGE" >&2; exit 1 ;;
  esac
  shift
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPECS="$PROJECT_ROOT/_docs/ai/specs"
REGISTER="$SPECS/ADDENDA.md"
TEMPLATE="$SPECS/templates/spec-addendum.template.md"
[[ -f "$TEMPLATE" ]] || { echo "new-addendum: $TEMPLATE missing - run the library's bootstrap.sh <project> --refresh-hooks to deliver the spec kit." >&2; exit 1; }
if [[ ! -f "$REGISTER" ]]; then
  printf '# Spec addenda register\n\n| ID | Date | Subject | Criteria touched | Authorised by | File |\n|---|---|---|---|---|---|\n' > "$REGISTER"
  echo "new-addendum: created $REGISTER"
fi

# spec slug: --spec, else the single *.spec.md in _docs/ai/specs/, else "spec"
if [[ -z "$SLUG" ]]; then
  _specs=( "$SPECS"/*.spec.md )
  if [[ ${#_specs[@]} -eq 1 && -f "${_specs[0]}" ]]; then SLUG="$(basename "${_specs[0]}" .spec.md)"; else SLUG="spec"; fi
fi

PY=""; PY_ARGS=()
# Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
[[ -z "$PY" ]] && { echo "new-addendum: Python 3 is required (python3/python/py not found)." >&2; exit 1; }

OUT="$(REGISTER_PATH="$REGISTER" TEMPLATE_PATH="$TEMPLATE" SPECS_DIR="$SPECS" SUBJECT_VAL="$SUBJECT" CRITERIA_VAL="$CRITERIA" BY_VAL="$BY" SLUG_VAL="$SLUG" pyc - <<'PYEOF'
import datetime, os, re, sys
reg = open(os.environ["REGISTER_PATH"], encoding="utf-8").read()
nums = [int(m) for m in re.findall(r"^\|\s*\**A(\d+)[a-z]?\**\s*\|", reg, re.M)]
n = (max(nums) + 1) if nums else 1
subject = os.environ["SUBJECT_VAL"].strip()
kebab = re.sub(r"[^a-z0-9]+", "-", subject.lower()).strip("-")[:48] or "addendum"
today = datetime.date.today().isoformat()
criteria = [c.strip() for c in os.environ.get("CRITERIA_VAL", "").split(",") if c.strip()]
by = os.environ.get("BY_VAL", "").strip() or "<name>"
slug = os.environ["SLUG_VAL"]
fname = f"{slug}.addendum-A{n}-{kebab}.md"
path = os.path.join(os.environ["SPECS_DIR"], fname)
if os.path.exists(path):
    print(f"new-addendum: {fname} already exists", file=sys.stderr); sys.exit(1)
tpl = open(os.environ["TEMPLATE_PATH"], encoding="utf-8").read()
if by != "<name>":
    tpl = tpl.replace("<name>, {{DATE}}", f"{by}, {{{{DATE}}}}")
body = (tpl.replace("{{N}}", str(n)).replace("{{SUBJECT}}", subject).replace("{{DATE}}", today)
           .replace("{{CRITERIA}}", ", ".join(criteria) if criteria else "<criteria>"))
open(path, "w", encoding="utf-8").write(body)
row = f"| A{n} | {today} | {subject} | {', '.join(criteria) if criteria else '(name them in the file)'} | {by} | `{fname}` |\n"
with open(os.environ["REGISTER_PATH"], "a", encoding="utf-8") as fh:
    if not reg.endswith("\n"): fh.write("\n")
    fh.write(row)
print(f"A{n}|{path}")
PYEOF
)"
NUM="${OUT%%|*}"; FILE="${OUT#*|}"
echo "new-addendum: allocated $NUM -> ${FILE#$PROJECT_ROOT/} (register row appended to _docs/ai/specs/ADDENDA.md)."
echo "Next: fill the authorization block FIRST; then scripts/set-criterion.sh <TG> <ID> --addendum $(date -u +%Y-%m-%d) for each criterion it touches; the test change travels in the same commit."
