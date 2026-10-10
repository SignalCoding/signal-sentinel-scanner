#!/usr/bin/env bash
#
# secrets-guard.sh (v1.8.1-cc)
#
# PreToolUse hook for Claude Code.
# Blocks Bash, Edit, Write, and MultiEdit tool calls that touch sensitive paths,
# contain destructive command patterns, or attempt data destruction without
# WHERE clauses.
#
# Stack-agnostic. Works on any project regardless of language or framework.
#
# Registered in each template's .claude/settings.json on PreToolUse.
# Matcher: Bash|PowerShell|Edit|Write|MultiEdit (v3.2.0: PowerShell is a tool on Windows; it gets
# every blocked-pattern check and NONE of the Bash-shaped read-only relaxations, plus its own
# destructive-verb set below)
#
# Exits 2 to block (stderr is fed back to Claude). Exits zero to allow.
# Logs allowed calls to _docs/ai/logs/tool-audit.log when the directory exists.
#
# Reads JSON from stdin (the hook payload).
# v1.8.1-cc: JSON parsing via Python (jq is often absent on Windows Git Bash);
# CLAUDE_PROJECT_DIR replaces the earlier tool-specific project-dir variable.
# v1.11.0: degraded environment (no Python 3) no longer skips the guard. The
# raw payload is scanned against every blocked-pattern list; a match on a
# secrets/destructive pattern fails CLOSED (exit 2). Only a clean raw scan
# fails open, loudly. The WHERE-less DELETE/UPDATE checks need a parsed
# command and are skipped in degraded mode (documented in hooks/README.md).
# v3.0.0 (folds the post-2.8.0 Augurpoint fixes): Windows-form paths (C:\proj\.env) are
# normalised to forward slashes before path matching - the forward-slash-only patterns silently
# bypassed the guard on Windows. False positives removed: the .git-directory pattern is anchored
# to a path segment and read-only plumbing (cat/ls/git rev-parse ...) is allowed; the .env
# pattern excludes .env.example/.sample/.template and never matched process.env; the bare words
# shutdown/mkfs/TRUNCATE are anchored to a command/statement position.
# v3.0.0 (TriTech harvest, four blocked commands in one session): a READ-ONLY command - a
# single line whose every pipe segment starts with a read-only verb (grep/rg/cat/find/ls/
# git log ...) and that carries no chaining, redirection or substitution - may mention
# lockfiles and destructive words (`grep -iE "truncate|drop table" -r src`,
# `find . -name packages.lock.json`). The secrets/.env/.git categories are NOT relaxed by it:
# reading a secret into context is the harm those guard. `git commit -m/-F` messages and
# `cat > file.md <<EOF` heredocs are prose, not SQL, and skip the SQL categories.

set -uo pipefail

# Read the tool input JSON
INPUT=$(cat)

PY=""; PY_ARGS=()
# Windows Python ends every line it prints with CR LF; pyc strips the CR from captured output
pyc() { "$PY" "${PY_ARGS[@]}" "$@" | tr -d '\r'; return "${PIPESTATUS[0]}"; }
for _c in python3 python py; do
  command -v "$_c" >/dev/null 2>&1 || continue
  [[ "$_c" == "py" ]] && _a=(-3) || _a=()
  # Reject non-functional interpreters (e.g. the Windows Store python3 alias stub)
  if "$_c" "${_a[@]}" -c "import sys" >/dev/null 2>&1; then PY="$_c"; PY_ARGS=("${_a[@]}"); break; fi
done
DEGRADED=0
if [[ -z "$PY" ]]; then
  # Degraded-environment policy (v1.11.0): do NOT silently skip the guard.
  # The raw payload is scanned below, after the pattern lists are defined:
  # secrets/destructive matches fail CLOSED, a clean scan fails open LOUDLY.
  DEGRADED=1
fi

# ============================================================
# Category 1: Sensitive paths (never touch)
# ============================================================
BLOCKED_PATHS=(
  # v2.0.1: Supabase service-role material on the COMMAND LINE (echo/export/curl of keys).
  # Best-effort only - this hook scans commands and file paths, never file contents; the
  # in-file case is review-caught (supabase CONSTITUTION tags it [S] accordingly).
  "sb_secret_"
  "SUPABASE_SERVICE_ROLE"
  # The .env file pattern and the .git-directory pattern live in their own lists below
  # (ENV_FILE_PATTERNS, GITDIR_PATTERNS) because each needs a targeted allow.
  "id_rsa"
  "id_ed25519"
  "id_ecdsa"
  "\.ssh/"
  "credentials\.json"
  "secrets\.json"
  "\.aws/"
  "\.azure/"
  "\.kube/"
  "\.docker/config\.json"
  "appsettings\.Production\.json"
  "appsettings\.Development\.json"
  "\.npmrc"
)

# ============================================================
# Category 1a: .env files (post-2.8.0 - split from Category 1)
# ============================================================
# v2.0.0 (D-09) anchoring kept: .env must be a filename token (start/space/slash/quote/= before;
# end/space/quote after, optionally with a dot-suffix such as .env.local), so ".environment",
# "dotenv" and "process.env" never match. post-2.8.0: the committed-by-design variants
# .env.example / .env.sample / .env.template are ALLOWED - env_strip_examples() rewrites them
# to a non-matching token before this list is applied (grep -E has no negative lookahead).
ENV_FILE_PATTERNS=(
  "(^|[/ \"'=])\.env(\.[A-Za-z0-9_.-]+)?([ \"']|$)"
)
env_strip_examples() {
  printf '%s\n' "$1" | sed -E 's/\.env\.(example|sample|template)\b/.env-example/g'
}

# ============================================================
# Category 1c: the .git directory (post-2.8.0 - split from Category 1)
# ============================================================
# Anchored to a path segment that IS the .git directory (start/slash/space/quote/= before), so
# "repo.git/" (a bare repo), "\.git/" inside a grep pattern or a prose mention never match.
# Read-only plumbing a coding agent legitimately needs (cat .git/HEAD, ls .git/hooks,
# git rev-parse --git-dir=.git/ ...) is allowed by the targeted allow-check below; edits and
# writes into the directory (Write/Edit tools, redirects, rm/sed -i/mv ...) stay blocked.
GITDIR_PATTERNS=(
  "(^|[/ \"'=])\.git/"
)

# ============================================================
# Category 1b: Lockfiles (v1.11.4 - split from Category 1)
# ============================================================
# Lockfiles must not be modified or deleted by the agent, but COMMITTING them is
# mandated by the package-supply-chain-safety skill - so safe, read-only/staging git
# verbs (add/commit/diff/status/restore --staged) are allowed on them via a targeted
# allow-check below, applied BEFORE these patterns. Everything else stays blocked.
LOCKFILE_PATTERNS=(
  "package-lock\.json"
  "pnpm-lock\.yaml"
  "yarn\.lock"
  "Gemfile\.lock"
  "Cargo\.lock"
  "poetry\.lock"
  "uv\.lock"
  "packages\.lock\.json"
)

# ============================================================
# Category 2: Destructive shell commands
# ============================================================
BLOCKED_COMMANDS=(
  "curl.*-d.*[a-zA-Z0-9]{30,}"
  "wget.*--post-data"
  "rm -rf /"
  "rm -rf \*"
  "rm -rf ~"
  "rm -rf \\$"
  # v2.0.0 (D-09): --force-with-lease is the SAFER push variant and is ALLOWED - blocking it
  # steered operators toward bare --force, which is strictly worse. Bare --force still blocks:
  # the pattern requires a non-hyphen (or end) after --force so -with-lease never matches.
  "git push[^|;&]*--force([^-]|$)"
  "git push.*-f "
  "git push.*-f$"
  "git reset --hard"
  # post-2.8.0: bare words anchored to a COMMAND position - start of line or after a separator
  # (; & | ( backtick), optional whitespace, optional sudo - so `grep -r shutdown src` or
  # `ls docs/mkfs-notes.md` no longer match. grep -E is per-line, so ^ also covers a command
  # that starts on a new line. (Degraded mode scans the bare words - see DEGRADED_BARE_WORDS.)
  "(^|[;&|(\`])[[:space:]]*(sudo[[:space:]]+)?shutdown([[:space:]]|$)"
  "(^|[;&|(\`])[[:space:]]*(sudo[[:space:]]+)?mkfs(\.[a-z0-9]+)?([[:space:]]|$)"
  "dd if=.*of=/dev"
)

# v3.2.0: PowerShell destructive verbs (the Bash set above is shaped for sh; these are the
# PowerShell equivalents). Applied only when tool_name is PowerShell. Path patterns (.env,
# .git, lockfiles) already apply to every tool through TARGET.
BLOCKED_POWERSHELL=(
  "Remove-Item[^|;]*-Recurse"
  "Remove-Item[^|;]*-Force"
  "(^|[;|&[:space:]])(rd|rmdir)[[:space:]]+/[sS]"
  "(^|[;|&[:space:]])(del|erase)[[:space:]]+/[sSqQfF]"
  "Format-Volume"
  "Clear-Content"
  "Remove-Item[^|;]*(\\.env|\\.git)"
  "git push[^|;&]*--force([^-]|$)"
  "git reset --hard"
)

# ============================================================
# Category 3: SQL schema destruction (DROP)
# ============================================================
BLOCKED_SQL_DROP=(
  "DROP[[:space:]]+TABLE"
  "DROP[[:space:]]+DATABASE"
  "DROP[[:space:]]+SCHEMA"
  "DROP[[:space:]]+INDEX"
  "DROP[[:space:]]+FUNCTION"
  "DROP[[:space:]]+PROCEDURE"
  "DROP[[:space:]]+TRIGGER"
  "DROP[[:space:]]+POLICY"
  "DROP[[:space:]]+RULE"
  "DROP[[:space:]]+TYPE"
  "DROP[[:space:]]+DOMAIN"
  "DROP[[:space:]]+VIEW"
  "DROP[[:space:]]+SEQUENCE"
  "DROP[[:space:]]+COLUMN"
)

# ============================================================
# Category 4: SQL data destruction (obvious patterns)
# ============================================================
BLOCKED_SQL_DATA=(
  "DELETE FROM.*WHERE.*1[[:space:]]*=[[:space:]]*1"
  "UPDATE.*SET.*WHERE.*1[[:space:]]*=[[:space:]]*1"
)
# v3.0.0: TRUNCATE lives in its own list and is matched CASE-SENSITIVELY (upper-case SQL
# keyword), so "truncated" in a commit message, `grep -i truncate` and coreutils `truncate`
# never qualify while `psql -c "TRUNCATE TABLE users"` still does.
BLOCKED_SQL_TRUNCATE=(
  # post-2.8.0: TRUNCATE as a STATEMENT - at start of line or after a separator/quote. Two
  # shapes: `TRUNCATE TABLE <ident>` (the keyword must be followed by an identifier, so the
  # search string `grep -rn "TRUNCATE TABLE" src` never matches), and `TRUNCATE <ident>` where
  # the identifier ends the statement (`;`, end of line, or a closing quote that ends the
  # command segment). `grep -rn TRUNCATE src` and coreutils `truncate -s 0 file` never match;
  # `psql -c "TRUNCATE TABLE users"` and `psql -c 'TRUNCATE users;'` still do.
  "(^|[;&|(\`\"'])[[:space:]]*TRUNCATE[[:space:]]+TABLE[[:space:]]+[A-Za-z_\`\"\[]"
  "(^|[;&|(\`\"'])[[:space:]]*TRUNCATE[[:space:]]+[A-Za-z_\`\[][A-Za-z0-9_.\`\]]*[[:space:]]*(;|$|[\"'][[:space:]]*($|[;&|]))"
)

# ============================================================
# Category 5: Tooling-specific destructive commands
# ============================================================
BLOCKED_TOOLING=(
  "supabase db reset"
  "supabase db push.*--force"
  "supabase projects delete"
  "supabase functions delete"
  "prisma migrate reset"
  "prisma db push.*--force-reset"
  "dotnet ef database drop"
  "rails db:drop"
  "flyway clean"
  "docker.*system prune.*-a.*-f"
  "kubectl delete namespace"
)

# ============================================================
# Degraded mode (no Python 3): raw-payload scan
# ============================================================
# The payload cannot be parsed into tool_name/command/file_path, so the RAW
# JSON is scanned against every blocked-pattern list. A match on any
# secrets/destructive pattern fails CLOSED (exit 2) - a false positive (the
# pattern appearing in file content) is an acceptable cost; a false negative
# on a destructive command is not. A clean scan fails open, LOUDLY.
# post-2.8.0: the raw payload is scanned with backslashes normalised to forward slashes
# (JSON-escaped C:\\proj\\.env -> C://proj//.env) so Windows-form paths match here too; the
# anchored shutdown/mkfs/TRUNCATE patterns cannot see a command boundary inside raw JSON, so
# the bare words are scanned as well (fail-closed on a false positive is this mode's policy).
DEGRADED_BARE_WORDS=("shutdown" "mkfs" "TRUNCATE")
RAW_SCAN="$(env_strip_examples "${INPUT//\\//}")"
if [[ "$DEGRADED" == "1" ]]; then
  for pattern in "${BLOCKED_PATHS[@]}" "${ENV_FILE_PATTERNS[@]}" "${GITDIR_PATTERNS[@]}" \
                 "${LOCKFILE_PATTERNS[@]}" "${BLOCKED_COMMANDS[@]}" \
                 "${BLOCKED_SQL_DROP[@]}" "${BLOCKED_SQL_DATA[@]}" "${BLOCKED_SQL_TRUNCATE[@]}" \
                 "${BLOCKED_TOOLING[@]}" "${DEGRADED_BARE_WORDS[@]}"; do
    if printf '%s' "$RAW_SCAN" | grep -qiE "$pattern"; then
      echo "BLOCKED by secrets-guard (DEGRADED mode - Python 3 not found): raw payload matched blocked pattern '$pattern'." >&2
      echo "Without a JSON engine the payload cannot be parsed precisely, so secrets/destructive matches fail CLOSED." >&2
      echo "Install Python 3 (python3/python/py) to restore precise parsing. If this match is a false positive (the pattern appears only inside file content), installing Python will clear it." >&2
      exit 2
    fi
  done
  echo "secrets-guard: WARNING - Python 3 not found; degraded raw-payload scan only (WHERE-less DELETE/UPDATE checks skipped). Install Python 3 to restore the full guard." >&2
  exit 0
fi

# Extract the tool name and inputs
eval "$(printf '%s' "$INPUT" | pyc -c '
import json, shlex, sys
d = json.load(sys.stdin)
ti = d.get("tool_input") or {}
print("TOOL_NAME=" + shlex.quote(d.get("tool_name") or ""))
print("COMMAND="   + shlex.quote(ti.get("command") or ""))
print("FILE_PATH=" + shlex.quote(ti.get("file_path") or ""))
' 2>/dev/null || echo 'PARSE_FAILED=1')"
# v1.11.1 (review C3): a JSON parse failure must NOT blank the scan target and fail open.
# Fall back to the same raw-payload scan as the no-Python path: secrets/destructive match
# on the raw payload fails CLOSED; otherwise fail open LOUDLY.
if [[ "${PARSE_FAILED:-0}" == "1" ]]; then
  for pattern in "${BLOCKED_PATHS[@]}" "${ENV_FILE_PATTERNS[@]}" "${GITDIR_PATTERNS[@]}" \
                 "${LOCKFILE_PATTERNS[@]}" "${BLOCKED_COMMANDS[@]}" \
                 "${BLOCKED_SQL_DROP[@]}" "${BLOCKED_SQL_DATA[@]}" "${BLOCKED_SQL_TRUNCATE[@]}" \
                 "${BLOCKED_TOOLING[@]}" "${DEGRADED_BARE_WORDS[@]}"; do
    if printf '%s' "$RAW_SCAN" | grep -qiE "$pattern"; then
      echo "secrets-guard: payload JSON unparseable AND raw payload matches a blocked pattern ('$pattern') - failing CLOSED." >&2
      exit 2
    fi
  done
  echo "secrets-guard: WARNING - payload JSON unparseable; precise scan impossible, raw scan clean. Failing open LOUDLY (v1.11.1)." >&2
  exit 0
fi

# post-2.8.0: Windows-form paths. Claude Code on Windows can report file_path (and commands
# can carry) backslash paths with a drive letter (C:\proj\.env, C:\proj\.git\config). Every
# path pattern is written with forward slashes, so normalise BEFORE matching - without this
# the guard was silently bypassed on Windows. COMMAND itself is matched as typed by the
# command-shape categories (2-5) below; only the combined path target is normalised.
FILE_PATH="${FILE_PATH//\\//}"

# Combined string for pattern matching
TARGET="${COMMAND//\\//} ${FILE_PATH}"

# ============================================================
# v3.0.0: read-only / prose command classification (relaxes categories 1b, 2, 3, 4, 5 ONLY).
# ============================================================
# Tokenised with shlex (quote-aware, punctuation split) so a `|` inside a grep pattern is not
# a pipe. READ-ONLY: every pipe segment starts with a read-only verb and no unquoted
# ; & && || > >> < << ( ) appears; find -delete/-exec/-ok and sed -i never qualify; a
# backtick or $( anywhere disqualifies. PROSE: `git commit ...` (message text) or a
# `cat > file.md <<EOF` heredoc - text carriers, not SQL.
CLASSIFY="$(COMMAND_VAL="$COMMAND" pyc - <<'PYEOF'
import os, re, shlex
cmd = os.environ.get("COMMAND_VAL", "")
ro = 0; prose = 0
first = cmd.split("\n", 1)[0]
if re.match(r"^\s*cat\s*>>?\s*[^\s>]+\.(md|txt)\s*<<-?\s*['\"]?\w+['\"]?\s*$", first):
    prose = 1
try:
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True); lex.whitespace_split = True
    toks = list(lex)
except ValueError:
    toks = None
if toks is not None and "\n" not in cmd and "`" not in cmd and "$(" not in cmd:
    PUNCT = {";", "&", "&&", "||", ">", ">>", "<", "<<", "<<<", "(", ")", "|&", "&>", ">&"}
    if not any(t in PUNCT for t in toks):
        if len(toks) >= 2 and toks[0] == "git" and toks[1] == "commit":
            prose = 1
        segs, cur = [], []
        for t in toks:
            if t == "|": segs.append(cur); cur = []
            else: cur.append(t)
        segs.append(cur)
        RO = {"grep","egrep","fgrep","rg","ag","cat","head","tail","less","more","wc","stat","ls","tree","find",
              "test","[","[[","file","diff","cmp","sort","uniq","cut","tr","column","jq","sed","awk","realpath",
              "readlink","du","xxd","od","strings","basename","dirname","echo","printf","which","type"}
        GIT_RO = {"grep","log","show","diff","status","ls-files","rev-parse","blame","cat-file","describe","branch",
                  "tag","remote","stash","worktree","config","check-ignore","for-each-ref"}
        ok = bool(segs) and all(seg for seg in segs)
        for seg in segs:
            if not ok: break
            v = seg[0]
            if v == "git":
                rest = [t for t in seg[1:] if not t.startswith("-")]
                sub = rest[0] if rest else ""
                if sub not in GIT_RO: ok = False
                elif sub in ("stash","worktree") and (len(rest) < 2 or rest[1] != "list"): ok = False
                elif sub == "config" and not any(t in ("--get","--list","-l") for t in seg): ok = False
            elif v in RO:
                if v == "find" and any(t in ("-delete","-exec","-execdir","-ok","-okdir") for t in seg): ok = False
                if v == "sed" and any(t == "--in-place" or (t.startswith("-") and not t.startswith("--") and "i" in t) for t in seg): ok = False
            else:
                ok = False
        ro = 1 if ok else 0
print(f"{ro} {prose}")
PYEOF
)"
READ_ONLY_CMD="${CLASSIFY%% *}"; PROSE_CMD="${CLASSIFY##* }"
[[ "$TOOL_NAME" == "Bash" && -z "$FILE_PATH" && -n "$COMMAND" ]] || { READ_ONLY_CMD=0; PROSE_CMD=0; }

# Function: check patterns against a target string
# Args: pattern_array_name target_string category_label
check_patterns() {
  # v3.0.1: indirect expansion instead of `local -n` (bash 4.3+) so the guard also runs on a
  # stock macOS /bin/bash 3.2 - a nameref error there made the guard FAIL OPEN.
  local _arr="$1[@]"
  local target="$2"
  local category="$3"

  for pattern in "${!_arr}"; do
    if echo "$target" | grep -qiE "$pattern"; then
      echo "BLOCKED by secrets-guard ($category): matched pattern '$pattern'" >&2
      echo "Tool: $TOOL_NAME" >&2
      echo "Target: $target" >&2
      return 1
    fi
  done
  return 0
}

# Case-sensitive variant (v3.0.0): SQL keywords that collide with English words.
check_patterns_cs() {
  local _arr="$1[@]"
  local target="$2"
  local category="$3"
  for pattern in "${!_arr}"; do
    if echo "$target" | grep -qE "$pattern"; then
      echo "BLOCKED by secrets-guard ($category): matched pattern '$pattern'" >&2
      echo "Tool: $TOOL_NAME" >&2
      echo "Target: $target" >&2
      return 1
    fi
  done
  return 0
}

# Check sensitive paths
check_patterns BLOCKED_PATHS "$TARGET" "sensitive path" || exit 2

# .env files (post-2.8.0): example/sample/template variants are allowed, everything else blocks.
check_patterns ENV_FILE_PATTERNS "$(env_strip_examples "$TARGET")" \
  "sensitive path - .env file (.env.example/.sample/.template are allowed)" || exit 2

# ============================================================
# .git directory check (post-2.8.0): targeted allow for read-only plumbing.
# ============================================================
# A plain Bash command that STARTS with a read-only verb, names no file_path (Edit/Write into
# .git/ stay blocked), is a single line and carries no chaining/redirection/substitution
# metacharacters (; & | > < ` $( )) may mention the .git directory: cat .git/HEAD,
# ls .git/hooks, test -f .git/hooks/pre-commit, git rev-parse/log/status/... . Anything that
# could write (rm, mv, cp, sed -i, tee, echo >, find -delete ...) never matches the allow.
GITDIR_READ_ALLOWED=0
if [[ "$TOOL_NAME" == "Bash" && -z "$FILE_PATH" && "$COMMAND" != *$'\n'* ]] \
   && ! printf '%s\n' "$COMMAND" | grep -qE '[;&|<>`]|\$\('; then
  if printf '%s\n' "$COMMAND" | grep -qE '^[[:space:]]*(cat|ls|head|tail|stat|wc|file|grep|rg|test|\[\[?|du|realpath|readlink|cmp|diff)([[:space:]]|$)'; then
    GITDIR_READ_ALLOWED=1
  elif printf '%s\n' "$COMMAND" | grep -qE '^[[:space:]]*git[[:space:]]+(-C[[:space:]]+[^[:space:]]+[[:space:]]+)?(--git-dir=[^[:space:]]+[[:space:]]+)?(rev-parse|status|log|diff|show|ls-files|cat-file|describe|check-ignore|for-each-ref|worktree[[:space:]]+list|config[[:space:]]+--(get|list))([[:space:]]|$)'; then
    GITDIR_READ_ALLOWED=1
  fi
fi
if [[ "$GITDIR_READ_ALLOWED" != "1" ]]; then
  check_patterns GITDIR_PATTERNS "$TARGET" \
    "sensitive path - .git directory (read-only plumbing such as cat/ls/git rev-parse is allowed; writes are not)" || exit 2
fi

# ============================================================
# Lockfile check (v1.11.4): targeted allow BEFORE the lockfile patterns.
# ============================================================
# The supply-chain skill MANDATES committing lockfiles, so a plain Bash git command
# using only safe verbs (add / commit / diff / status / restore --staged) is allowed
# even when it names a lockfile. The allow is deliberately narrow:
#   - Bash tool only, with no file_path (Edit/Write on lockfiles stay blocked);
#   - the command must START with the git verb (no prefix commands);
#   - no chaining/substitution metacharacters (; & | > < ` $( )) that could smuggle a
#     destructive operation alongside the safe git verb;
#   - `git restore` only with --staged and without --worktree/-W (a worktree restore
#     rewrites the file's content).
# Destructive/modifying operations (rm, redirects, sed -i, mv over, etc.) never match
# the allow and fall through to the block below. No other category is touched.
LOCKFILE_GIT_ALLOWED=0
if [[ "$TOOL_NAME" == "Bash" && -z "$FILE_PATH" && "$COMMAND" != *$'\n'* ]]; then
  if printf '%s\n' "$COMMAND" | grep -qE '^[[:space:]]*git[[:space:]]+(add|commit|diff|status)([[:space:]]|$)'; then
    LOCKFILE_GIT_ALLOWED=1
  elif printf '%s\n' "$COMMAND" | grep -qE '^[[:space:]]*git[[:space:]]+restore[[:space:]]+--staged([[:space:]]|$)' \
       && ! printf '%s\n' "$COMMAND" | grep -qE '(^|[[:space:]])(--worktree|-W)([[:space:]]|$)'; then
    LOCKFILE_GIT_ALLOWED=1
  fi
  if [[ "$LOCKFILE_GIT_ALLOWED" == "1" ]] \
     && printf '%s\n' "$COMMAND" | grep -qE '[;&|<>`]|\$\('; then
    LOCKFILE_GIT_ALLOWED=0   # chained/compound command: not provably safe
  fi
fi
if [[ "$LOCKFILE_GIT_ALLOWED" != "1" && "$READ_ONLY_CMD" != "1" ]]; then
  check_patterns LOCKFILE_PATTERNS "$TARGET" "lockfile - only safe git verbs (add/commit/diff/status/restore --staged) and read-only commands may name lockfiles" || exit 2
fi

if [[ "$READ_ONLY_CMD" != "1" ]]; then
  # Check destructive shell commands
  check_patterns BLOCKED_COMMANDS "$COMMAND" "destructive command" || exit 2

  if [[ "$PROSE_CMD" != "1" ]]; then
    # Check SQL schema destruction
    check_patterns BLOCKED_SQL_DROP "$COMMAND" "SQL schema destruction" || exit 2

    # Check SQL data destruction (obvious patterns). v3.0.0: TRUNCATE is matched as the
    # upper-case SQL keyword only - "truncated" in prose and `truncate -s` never qualify.
    check_patterns BLOCKED_SQL_DATA "$COMMAND" "SQL data destruction" || exit 2
    check_patterns_cs BLOCKED_SQL_TRUNCATE "$COMMAND" "SQL data destruction" || exit 2

    # Check WHERE-less DELETE FROM (special case: needs negative check)
    if echo "$COMMAND" | grep -qiE "DELETE[[:space:]]+FROM[[:space:]]+[a-zA-Z_\"\.]+"; then
      if ! echo "$COMMAND" | grep -qiE "WHERE"; then
        echo "BLOCKED by secrets-guard (SQL data destruction): DELETE FROM without WHERE clause" >&2
        echo "Tool: $TOOL_NAME" >&2
        echo "Command: $COMMAND" >&2
        exit 2
      fi
    fi

    # Check WHERE-less UPDATE (special case: needs negative check)
    if echo "$COMMAND" | grep -qiE "UPDATE[[:space:]]+[a-zA-Z_\"\.]+[[:space:]]+SET"; then
      if ! echo "$COMMAND" | grep -qiE "WHERE"; then
        echo "BLOCKED by secrets-guard (SQL data destruction): UPDATE without WHERE clause" >&2
        echo "Tool: $TOOL_NAME" >&2
        echo "Command: $COMMAND" >&2
        exit 2
      fi
    fi
  fi

  # Check tooling-specific destructive commands
  check_patterns BLOCKED_TOOLING "$COMMAND" "destructive tooling command" || exit 2

  # v3.2.0: PowerShell destructive verbs
  if [[ "$TOOL_NAME" == "PowerShell" ]]; then
    check_patterns BLOCKED_POWERSHELL "$COMMAND" "destructive PowerShell command" || exit 2
  fi
fi

# ============================================================
# Allowed: log to audit trail if project has _docs/ai/logs
# ============================================================
# v3.2.0: data minimisation. The audit line carries the tool, a target CLASS (the command's
# first word, or the file path for file tools) and a 12-hex sha256 of the full target, never
# the command text: an allowed command can carry a token, a query or a path the repository
# should not hold, and this log is committed. The hash lets a reviewer match a line to a
# command they hold without the log holding it.
AUDIT_DIR="${CLAUDE_PROJECT_DIR:-$PWD}/_docs/ai/logs"
if [ -d "$AUDIT_DIR" ]; then
  if [[ "$TOOL_NAME" == "Bash" || "$TOOL_NAME" == "PowerShell" ]]; then
    _class="$(printf '%s' "$COMMAND" | awk 'NR==1{print $1; exit}')"; _class="${_class:-command}"
  else
    _class="${FILE_PATH:-no-path}"
  fi
  _hash="$(TARGET_VAL="$TARGET" pyc -c 'import hashlib,os; print(hashlib.sha256(os.environ["TARGET_VAL"].encode("utf-8","replace")).hexdigest()[:12])' 2>/dev/null || echo "unhashed")"
  echo "$(date -Iseconds) ALLOW $TOOL_NAME $_class sha256:$_hash" >> "$AUDIT_DIR/tool-audit.log"
fi

exit 0
