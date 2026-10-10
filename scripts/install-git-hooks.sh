#!/usr/bin/env bash
# Installs the v1.7 pre-commit hook: verify-gate must pass before any commit.
# v3.0.0: the pre-commit hook runs the gate with VERIFY_GATE_SCOPE=staged (vacuous-gate guard
# over the files being committed). Re-running this script on a v2.x project backs up the old
# hook and installs the new one - bootstrap.sh --refresh-hooks calls it for you.
# v2.8.0 (repo-standards): ALSO installs a dependency-free commit-msg hook enforcing
# Conventional Commits 1.0.0 (type(scope)!: lower-case imperative, <=72 chars, no trailing
# full stop). Same hooksPath/backup/idempotence rules as the pre-commit hook.
# v1.11.4: worktree-safe (git rev-parse --git-dir, not [[ -d .git ]]); respects
# core.hooksPath (installs there when the directory is free, or prints the manual
# chaining step when a hook manager already owns pre-commit); backs up any existing
# pre-commit to pre-commit.backup-<epoch> before writing; and never reports
# "installed" unless the hook was actually written.
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Worktree-safe repo detection: in a linked worktree .git is a FILE, so [[ -d .git ]]
# wrongly failed there. rev-parse resolves both layouts; hooks live under the COMMON
# git dir (shared across worktrees), so that is where the hook must be written.
git -C "$PROJECT_ROOT" rev-parse --git-dir >/dev/null 2>&1 || {
  echo "Not a git repository: $PROJECT_ROOT" >&2
  exit 1
}
GIT_DIR="$(git -C "$PROJECT_ROOT" rev-parse --git-common-dir 2>/dev/null)" \
  || GIT_DIR="$(git -C "$PROJECT_ROOT" rev-parse --git-dir)"
case "$GIT_DIR" in
  /*) ;;
  *) GIT_DIR="$PROJECT_ROOT/$GIT_DIR" ;;
esac

HOOK_CONTENT='#!/usr/bin/env bash
# evidence gate - Tier B (staged scope so the vacuous-gate guard sees this commit)
VERIFY_GATE_SCOPE=staged "$(git rev-parse --show-toplevel)/scripts/verify-gate.sh" || exit $?
# A pre-commit hook that was here before the gate was installed runs AFTER it, from
# pre-commit.local (install-git-hooks.sh moves it there; the gate never displaces a hook).
_local="$(cd "$(dirname "$0")" && pwd)/pre-commit.local"
[ -x "$_local" ] && exec "$_local" "$@"
exit 0
'

# Respect core.hooksPath: if a hook manager (husky, lefthook, ...) or a custom hooks
# directory is configured, git will ONLY run hooks from there - writing to
# $GIT_DIR/hooks would be silently ignored, and clobbering the manager's pre-commit
# would break it.
HOOKS_DIR="$GIT_DIR/hooks"
HOOKS_PATH_CFG="$(git -C "$PROJECT_ROOT" config --get core.hooksPath 2>/dev/null || true)"
if [[ -n "$HOOKS_PATH_CFG" ]]; then
  HOOKS_DIR="$HOOKS_PATH_CFG"
  [[ "$HOOKS_DIR" == "~/"* ]] && HOOKS_DIR="$HOME/${HOOKS_DIR#\~/}"
  case "$HOOKS_DIR" in
    /*) ;;
    *) HOOKS_DIR="$PROJECT_ROOT/$HOOKS_DIR" ;;   # core.hooksPath is relative to the worktree root
  esac
  if [[ -f "$HOOKS_DIR/pre-commit" ]] && ! printf '%s' "$HOOK_CONTENT" | cmp -s - "$HOOKS_DIR/pre-commit"; then
    echo "NOT installed: core.hooksPath is set ($HOOKS_PATH_CFG) and a pre-commit hook already exists there." >&2
    echo "A hook manager appears to own hooks in this repository; overwriting its pre-commit would break it." >&2
    echo "Manual step - chain the verify gate from that manager's pre-commit by adding:" >&2
    echo '    VERIFY_GATE_SCOPE=staged "$(git rev-parse --show-toplevel)/scripts/verify-gate.sh" || exit 1' >&2
    exit 1
  fi
  echo "NOTE: core.hooksPath is set ($HOOKS_PATH_CFG); installing the hook there (git ignores $GIT_DIR/hooks)."
fi

mkdir -p "$HOOKS_DIR"
HOOK="$HOOKS_DIR/pre-commit"

PRECOMMIT_DONE=0
if [[ -f "$HOOK" ]]; then
  if printf '%s' "$HOOK_CONTENT" | cmp -s - "$HOOK"; then
    chmod +x "$HOOK"
    echo "Pre-commit verify-gate already installed at $HOOK (unchanged)."
    PRECOMMIT_DONE=1   # v2.8.0: fall through to the commit-msg hook instead of exiting
  elif grep -q "scripts/verify-gate.sh" "$HOOK" 2>/dev/null; then
    # an earlier version of THIS hook: replace it (backup kept)
    BACKUP="$HOOK.backup-$(date +%s)"
    cp "$HOOK" "$BACKUP"
    echo "Existing pre-commit (earlier verify-gate version) backed up to $BACKUP"
  else
    # v3.2.0: a FOREIGN hook (the project's own pre-commit, a linter, a hook manager's shim)
    # is chained, not displaced: it moves to pre-commit.local and the gate runs first.
    LOCAL="$HOOKS_DIR/pre-commit.local"
    if [[ -e "$LOCAL" ]] && ! cmp -s "$HOOK" "$LOCAL"; then
      echo "NOT installed: $HOOK is not the verify gate and $LOCAL already exists with different content." >&2
      echo "Merge the two hooks by hand (the gate chains to pre-commit.local), then re-run." >&2
      exit 1
    fi
    BACKUP="$HOOK.backup-$(date +%s)"
    cp "$HOOK" "$BACKUP"
    mv "$HOOK" "$LOCAL"
    chmod +x "$LOCAL"
    echo "Existing pre-commit moved to $LOCAL (backup $BACKUP); the verify gate runs first and then chains to it."
  fi
fi

if [[ "$PRECOMMIT_DONE" -eq 0 ]]; then
  printf '%s' "$HOOK_CONTENT" > "$HOOK"
  chmod +x "$HOOK"
  echo "Installed pre-commit verify-gate at $HOOK"
fi

# ------------------------------------------------------------------
# v2.8.0: commit-msg hook (Conventional Commits, no Node required)
# ------------------------------------------------------------------
COMMIT_MSG_CONTENT='#!/usr/bin/env sh
# v2.8.0 repo-standards - Conventional Commits 1.0.0 gate (dependency-free)
MSG_FILE="$1"
HEADER=$(sed -n "1p" "$MSG_FILE")
case "$HEADER" in
  "Merge "*|"Revert \""*|"fixup! "*|"squash! "*|"chore(main): release"*|"chore(release): "*) exit 0 ;;
esac
TYPES="feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert"
PATTERN="^($TYPES)(\([a-z0-9._/-]+\))?!?: [a-z0-9].{0,70}[^.]$"
if ! printf "%s" "$HEADER" | grep -Eq "$PATTERN"; then
  printf "\ncommit-msg: rejected. Expected Conventional Commits 1.0.0:\n" >&2
  printf "  <type>[optional scope][!]: <lower-case imperative description, <=72 chars, no trailing full stop>\n" >&2
  printf "  types: %s\n  e.g.   feat(auth): add magic-link sign in\n         fix!: reject expired tokens\n" "$TYPES" >&2
  printf "Your header: %s\n\n" "$HEADER" >&2
  exit 1
fi
'
CM_HOOK="$HOOKS_DIR/commit-msg"
if [[ -f "$CM_HOOK" ]]; then
  if printf '%s' "$COMMIT_MSG_CONTENT" | cmp -s - "$CM_HOOK"; then
    chmod +x "$CM_HOOK"
    echo "Commit-msg conventional-commits hook already installed at $CM_HOOK (unchanged)."
    exit 0
  fi
  if [[ -n "$HOOKS_PATH_CFG" ]]; then
    echo "NOT installed: a commit-msg hook already exists under core.hooksPath ($HOOKS_PATH_CFG)." >&2
    echo "Chain it from your hook manager: run the Conventional Commits check from scripts/ or commitlint (see CONTRIBUTING.md)." >&2
    exit 1
  fi
  CM_BACKUP="$CM_HOOK.backup-$(date +%s)"
  cp "$CM_HOOK" "$CM_BACKUP"
  echo "Existing commit-msg backed up to $CM_BACKUP"
fi
printf '%s' "$COMMIT_MSG_CONTENT" > "$CM_HOOK"
chmod +x "$CM_HOOK"
echo "Installed commit-msg conventional-commits hook at $CM_HOOK"
