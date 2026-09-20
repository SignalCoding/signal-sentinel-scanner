#!/usr/bin/env sh
# Signal Sentinel Scanner - Claude Code hook (SessionStart + PreToolUse/Skill).
#
# Claude Code passes a JSON event on stdin. This script:
#   SessionStart : scans the project's .claude/skills and .mcp.json (offline),
#                  prints a summary, never blocks.
#   PreToolUse   : when the tool is "Skill", re-scans the named skill directory
#                  and exits 2 (block) on any High or Critical finding.
#
# Install: see hooks/claude-code/README.md for the settings.json snippet.

set -eu

if ! command -v sentinel-scan >/dev/null 2>&1; then
    echo "sentinel-scan not installed. Run: dotnet tool install -g SignalSentinel.Scanner" >&2
    exit 0
fi

INPUT="$(cat 2>/dev/null || true)"
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"

# Minimal JSON field reader: prefers jq, falls back to sed for flat string fields.
json_field() {
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$INPUT" | jq -r "$1 // empty" 2>/dev/null || true
    else
        key="$(printf '%s' "$1" | sed 's/.*\.//')"
        printf '%s' "$INPUT" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n 1
    fi
}

EVENT="$(json_field '.hook_event_name')"
TOOL="$(json_field '.tool_name')"

case "$EVENT" in
    SessionStart)
        set -- --offline --format markdown --min-confidence 0.75
        if [ -d "$PROJECT_DIR/.claude/skills" ]; then
            set -- "$@" --skills "$PROJECT_DIR/.claude/skills"
        fi
        if [ -f "$PROJECT_DIR/.mcp.json" ]; then
            set -- "$@" --config "$PROJECT_DIR/.mcp.json"
        fi
        if [ "$#" -le 5 ]; then
            exit 0
        fi
        # Informational only at session start: report, never block.
        sentinel-scan "$@" >&2 || true
        exit 0
        ;;

    PreToolUse)
        if [ "$TOOL" != "Skill" ]; then
            exit 0
        fi
        SKILL="$(json_field '.tool_input.skill')"
        # Skill names are directory names; refuse anything that could traverse.
        case "$SKILL" in
            ""|*/*|*\\*|.*) exit 0 ;;
        esac
        for base in "$PROJECT_DIR/.claude/skills" "$HOME/.claude/skills"; do
            if [ -f "$base/$SKILL/SKILL.md" ]; then
                if sentinel-scan --offline --skills "$base/$SKILL" --format markdown \
                        --min-confidence 0.75 --fail-on high >&2; then
                    exit 0
                fi
                echo "Signal Sentinel blocked skill '$SKILL': High or Critical finding (see report above)." >&2
                exit 2
            fi
        done
        exit 0
        ;;

    *)
        exit 0
        ;;
esac
