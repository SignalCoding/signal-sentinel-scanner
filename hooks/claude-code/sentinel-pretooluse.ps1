# Signal Sentinel Scanner - Claude Code hook (SessionStart + PreToolUse/Skill), PowerShell edition.
#
# Claude Code passes a JSON event on stdin. This script:
#   SessionStart : scans the project's .claude/skills and .mcp.json (offline),
#                  prints a summary, never blocks.
#   PreToolUse   : when the tool is "Skill", re-scans the named skill directory
#                  and exits 2 (block) on any High or Critical finding.
#
# Install: see hooks/claude-code/README.md for the settings.json snippet.

$ErrorActionPreference = 'Stop'

if (-not (Get-Command sentinel-scan -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine('sentinel-scan not installed. Run: dotnet tool install -g SignalSentinel.Scanner')
    exit 0
}

$raw = [Console]::In.ReadToEnd()
try {
    $event = $raw | ConvertFrom-Json -ErrorAction Stop
} catch {
    exit 0
}

$projectDir = if ($env:CLAUDE_PROJECT_DIR) { $env:CLAUDE_PROJECT_DIR } else { (Get-Location).Path }

switch ($event.hook_event_name) {
    'SessionStart' {
        $scanArgs = @('--offline', '--format', 'markdown', '--min-confidence', '0.75')
        $skillsDir = Join-Path $projectDir '.claude/skills'
        $mcpJson = Join-Path $projectDir '.mcp.json'
        if (Test-Path -LiteralPath $skillsDir -PathType Container) { $scanArgs += @('--skills', $skillsDir) }
        if (Test-Path -LiteralPath $mcpJson -PathType Leaf) { $scanArgs += @('--config', $mcpJson) }
        if ($scanArgs.Count -le 5) { exit 0 }
        # Informational only at session start: report, never block.
        & sentinel-scan @scanArgs 2>&1 | ForEach-Object { [Console]::Error.WriteLine($_) }
        exit 0
    }

    'PreToolUse' {
        if ($event.tool_name -ne 'Skill') { exit 0 }
        $skill = [string]$event.tool_input.skill
        # Skill names are directory names; refuse anything that could traverse.
        if ([string]::IsNullOrWhiteSpace($skill) -or $skill -match '[\\/]' -or $skill.StartsWith('.')) { exit 0 }

        $bases = @((Join-Path $projectDir '.claude/skills'), (Join-Path $HOME '.claude/skills'))
        foreach ($base in $bases) {
            $skillDir = Join-Path $base $skill
            if (-not (Test-Path -LiteralPath (Join-Path $skillDir 'SKILL.md') -PathType Leaf)) { continue }

            & sentinel-scan --offline --skills $skillDir --format markdown --min-confidence 0.75 --fail-on high 2>&1 |
                ForEach-Object { [Console]::Error.WriteLine($_) }
            if ($LASTEXITCODE -eq 0) { exit 0 }

            [Console]::Error.WriteLine("Signal Sentinel blocked skill '$skill': High or Critical finding (see report above).")
            exit 2
        }
        exit 0
    }

    default { exit 0 }
}
