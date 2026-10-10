#!/usr/bin/env bash
#
# format-on-save.sh
#
# PostToolUse hook for Claude Code.
# Auto-formats files after Write, Edit, or MultiEdit tool calls.
# Supports common file types across stacks.
#
# Registered in each template's .claude/settings.json on PostToolUse.
# Matcher: Write|Edit|MultiEdit
#
# Best-effort: silently skips if the relevant formatter is not installed.
# v1.8.1-cc: JSON parsing via Python (jq is often absent on Windows Git Bash).
# v3.0.0 (TriTech harvest): governance artefacts are NEVER reformatted - the scripts serialise
# _docs/ai/verify/*.json with Python json.dumps(indent=2) and a prettier pass produced a
# 118-line diff on verify-results.json after every edit. Excluded by path: _docs/ai/**, .claude/**,
# CLAUDE.md, AGENTS.md, CONSTITUTION.md, lockfiles, CHANGELOG.md (release-please owns it) and
# anything a project .prettierignore lists (prettier honours it; the hook checks it too so the
# exclusion holds for the non-prettier branches).

set -uo pipefail

INPUT=$(cat)
# v3.3.0: decide from the raw payload before any interpreter starts. Most edits touch files no
# formatter handles (governance records, evidence, lockfiles, text), and on Windows the Python
# probe alone costs more than the edit. A bash regex reads file_path; an unhandled extension or
# an excluded path exits here, and only a formattable file pays for the JSON parse below.
if [[ "$INPUT" =~ \"file_path\"[[:space:]]*:[[:space:]]*\"((\\.|[^\"\\])*)\" ]]; then
  _QUICK="${BASH_REMATCH[1]//\\\\//}"; _QUICK="${_QUICK//\\//}"
  case "$_QUICK" in
    */_docs/ai/*|*/.claude/*|_docs/ai/*|.claude/*|*/CLAUDE.md|*/AGENTS.md|*/CONSTITUTION.md|*/CHANGELOG.md|CLAUDE.md|AGENTS.md|CONSTITUTION.md|CHANGELOG.md) exit 0 ;;
    *.ts|*.tsx|*.js|*.jsx|*.json|*.md|*.css|*.scss|*.html|*.yaml|*.yml|*.cs|*.razor|*.xaml|*.py|*.go|*.rs|*.sh) ;;
    *) exit 0 ;;
  esac
else
  exit 0
fi

PY=""; PY_ARGS=()
# Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  # Reject non-functional interpreters (e.g. the Windows Store python3 alias stub)
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
[[ -z "$PY" ]] && exit 0

FILE_PATH="$(printf '%s' "$INPUT" | pyc -c '
import json,sys
d=json.load(sys.stdin)
print((d.get("tool_input") or {}).get("file_path") or "")
' 2>/dev/null || echo "")"

# Skip if no file path
if [ -z "$FILE_PATH" ]; then
  exit 0
fi

# Skip if file does not exist (could happen on a failed edit)
if [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

# v3.0.0: governance / generated artefacts are not formatter targets.
_NORM="${FILE_PATH//\\//}"
case "$_NORM" in
  */_docs/ai/*|*/.claude/*|*/CLAUDE.md|*/AGENTS.md|*/CONSTITUTION.md|*/CHANGELOG.md|*/.release-please-manifest.json| \
  */package-lock.json|*/pnpm-lock.yaml|*/yarn.lock|*/packages.lock.json| \
  _docs/ai/*|.claude/*|CLAUDE.md|AGENTS.md|CONSTITUTION.md|CHANGELOG.md)
    exit 0 ;;
esac
# A project .prettierignore is honoured for every branch, not only the prettier one.
_PROOT="${CLAUDE_PROJECT_DIR:-$PWD}"
if [[ -f "$_PROOT/.prettierignore" ]]; then
  _REL="${_NORM#"${_PROOT//\\//}"/}"
  while IFS= read -r _pat; do
    _pat="${_pat%%#*}"; _pat="${_pat%"${_pat##*[![:space:]]}"}"
    [[ -z "$_pat" ]] && continue
    _pat="${_pat#/}"
    case "$_REL" in
      $_pat|$_pat/*|${_pat%/}|${_pat%/}/*) exit 0 ;;
    esac
  done < "$_PROOT/.prettierignore"
fi

# Format by file type
case "$FILE_PATH" in
  *.ts|*.tsx|*.js|*.jsx|*.json|*.md|*.css|*.scss|*.html|*.yaml|*.yml)
    if command -v npx >/dev/null 2>&1; then
      npx --no-install prettier --write "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
  *.cs|*.razor|*.xaml)
    # v1.11.3 (L-05): scope dotnet format to the OWNING project - unscoped it searches the
    # whole working directory (slow per save, can fail outright in multi-project layouts,
    # and the redirect+|| true hid that). Walk up to the nearest .csproj; no project, no run
    # (build-time formatting still enforces).
    if command -v dotnet >/dev/null 2>&1; then
      _dir="$(dirname "$FILE_PATH")"
      _proj=""
      while [[ -n "$_dir" && "$_dir" != "/" && "$_dir" != "." ]]; do
        _c=$(ls "$_dir"/*.csproj 2>/dev/null | head -1)
        [[ -n "$_c" ]] && { _proj="$_c"; break; }
        _dir="$(dirname "$_dir")"
      done
      if [[ -n "$_proj" ]]; then
        dotnet format "$_proj" --include "$FILE_PATH" >/dev/null 2>&1 || true
      fi
    fi
    ;;
  *.py)
    if command -v ruff >/dev/null 2>&1; then
      ruff format "$FILE_PATH" >/dev/null 2>&1 || true
    elif command -v black >/dev/null 2>&1; then
      black --quiet "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
  *.go)
    if command -v gofmt >/dev/null 2>&1; then
      gofmt -w "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
  *.rs)
    if command -v rustfmt >/dev/null 2>&1; then
      rustfmt "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
  *.sh)
    if command -v shfmt >/dev/null 2>&1; then
      shfmt -w "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
esac

exit 0
