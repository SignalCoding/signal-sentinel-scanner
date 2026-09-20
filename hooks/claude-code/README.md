# Signal Sentinel hook for Claude Code

Two events, one script (`.sh` for macOS/Linux/WSL, `.ps1` for Windows PowerShell):

| Event | Matcher | Behaviour |
|---|---|---|
| `SessionStart` | (none) | Scans the project's `.claude/skills` and `.mcp.json` offline and prints the report to stderr. Never blocks. |
| `PreToolUse` | `Skill` | Re-scans the named skill (`.claude/skills/<name>` in the project, then `~/.claude/skills/<name>`). Exits **2** on any High or Critical finding, which blocks the tool call and feeds the report back to Claude. |

Both run with `--offline --min-confidence 0.75` so the hook makes no network calls and
ignores triage-grade findings.

## Install

Copy `hooks/claude-code/` into your project (or reference it from this repo), then add
to `.claude/settings.json` (project) or `~/.claude/settings.json` (user):

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "sh hooks/claude-code/sentinel-pretooluse.sh" }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Skill",
        "hooks": [
          { "type": "command", "command": "sh hooks/claude-code/sentinel-pretooluse.sh", "timeout": 60 }
        ]
      }
    ]
  }
}
```

On Windows without a POSIX shell, use
`"command": "pwsh -NoProfile -File hooks/claude-code/sentinel-pretooluse.ps1"`.

## Prerequisite

```
dotnet tool install -g SignalSentinel.Scanner
```

The scripts exit 0 with a notice when `sentinel-scan` is not on `PATH`, so a missing
install never blocks a session.

## Tuning

- Block earlier: change `--fail-on high` to `--fail-on medium` in the `PreToolUse` branch.
- Quieter: add a `.sentinel-suppressions.json` with justified acceptances; the hook honours it.
- Skill names containing path separators or starting with `.` are ignored, never resolved.
