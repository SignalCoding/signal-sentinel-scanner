// -----------------------------------------------------------------------
// <copyright file="SkillScriptPayloadRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-016: Detects malicious patterns in bundled scripts (.py, .sh, .ps1, .js, .ts).
/// Checks for remote code execution, persistence mechanisms, and file system traversal.
/// Maps to OWASP ASI05 (Unexpected Code Execution).
/// </summary>
public sealed partial class SkillScriptPayloadRule : IRule
{
    public string Id => RuleConstants.Rules.SkillScriptPayload;
    public string Name => "Skill Script Payload Detection";
    public string OwaspCode => OwaspAsiCodes.ASI05;
    public string Description =>
        "Detects malicious patterns in bundled scripts including remote code download-and-execute, " +
        "persistence mechanisms, and file system traversal.";
    public bool EnabledByDefault => true;

    /// <summary>
    /// v3.0.0 (WP10): the document side of this rule evaluates fenced/indented code
    /// blocks and link destinations only; prose is documentation. Bundled scripts are
    /// scanned separately below.
    /// </summary>
    public SegmentKind ApplicableSegments => SegmentKind.FencedCode | SegmentKind.Link;

    [GeneratedRegex(
        @"(curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh|Invoke-WebRequest.*\|\s*Invoke-Expression|iwr.*\|\s*iex|curl\s+.*-o\s+\S+.*chmod\s+\+x)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex RemoteCodeExecution();

    // v2.5.1 tightened: ".profile" (and siblings) had no word boundary, so it matched
    // inside ordinary property-access expressions like "resp.profile" in JS/TS scripts -
    // a real-world review found 4 such false positives. A negative lookbehind now
    // requires the dotfile name not be preceded by a word character, so "resp.profile"
    // no longer matches while "~/.profile", "source .profile", etc. still do.
    [GeneratedRegex(
        @"(crontab|cron\.d|systemctl\s+enable|schtasks\s+/create|Register-ScheduledTask|(?<!\w)\.bashrc\b|(?<!\w)\.zshrc\b|(?<!\w)\.bash_profile\b|(?<!\w)\.profile\b|shell:startup|autostart|launchctl\s+load|launchd)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex PersistenceMechanism();

    [GeneratedRegex(
        @"(\.\.[\\/]\.\.[\\/]|/etc/|/usr/|/var/|/tmp/|C:\\Windows|C:\\Users|%USERPROFILE%|%APPDATA%|%TEMP%|\$HOME/\.\w)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex FileSystemTraversal();

    [GeneratedRegex(
        @"(os\.system\s*\(|subprocess\.\w+\s*\(|child_process\.exec|child_process\.spawn|Process\.Start|Runtime\.getRuntime\(\)\.exec|ShellExecute)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex ProcessExecution();

    private static readonly (Regex Pattern, string Name, Severity Severity, string Description, string Remediation)[] ScriptPatterns =
    [
        (RemoteCodeExecution(), "Remote Code Execution", Severity.Critical,
            "Detected download-and-execute pattern that retrieves and runs remote code",
            "Remove remote code execution patterns. Scripts should not download and execute external code."),
        (PersistenceMechanism(), "Persistence Mechanism", Severity.Critical,
            "Detected persistence mechanism that could install malware or modify startup configuration",
            "Remove persistence mechanisms. Skills should not modify system startup configuration."),
        (FileSystemTraversal(), "File System Traversal", Severity.High,
            "Detected file system traversal accessing paths outside the skill directory",
            "Restrict file access to the skill's own directory. Do not access system paths."),
        (ProcessExecution(), "Process Execution", Severity.High,
            "Detected process/command execution that could run arbitrary system commands",
            "Avoid direct process execution. Use safe, sandboxed alternatives where possible."),
    ];

    [GeneratedRegex(
        @"(/root/|/home/\w+/|C:\\Users\\|~/)[\w./-]+",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex AbsoluteUserPath();

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Scan bundled script files
            foreach (var script in skill.Scripts)
            {
                if (script.Content is null) continue;

                // v2.5.1: strip the shebang line before matching. FileSystemTraversal's
                // path alternatives include bare "/usr/" etc., which matched inside
                // every "#!/usr/bin/env ..." shebang - a real-world review found this
                // accounted for 170 of 240 script-payload false positives. A shebang
                // line is never itself meaningful evidence for any of these patterns,
                // so stripping it is safe for the whole ScriptPatterns pass.
                var scriptContent = StripShebangLine(script.Content);

                foreach (var (pattern, name, severity, description, remediation) in ScriptPatterns)
                {
                    if (SafeIsMatch(pattern, scriptContent))
                    {
                        var match = SafeMatches(pattern, scriptContent).FirstOrDefault();

                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = severity,
                            Title = $"Skill Script Payload: {name}",
                            Description = $"{description}. Found in '{script.RelativePath}' " +
                                $"({script.Language}) of skill '{skill.Name}'.",
                            Remediation = remediation,
                            ServerName = skill.Name,
                            ToolName = script.RelativePath,
                            Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                            Confidence = 0.9,
                            Source = FindingSource.Skill,
                            SkillFilePath = skill.FilePath
                        });
                    }
                }

                // Check shared obfuscation patterns in scripts
                if (InjectionPatterns.SafeIsMatch(ObfuscationPatterns.DynamicExecution(), scriptContent))
                {
                    // v2.5.1: this finding previously never populated Evidence at all,
                    // so there was no way to see what actually matched.
                    var obfuscationMatch = SafeMatches(ObfuscationPatterns.DynamicExecution(), scriptContent)
                        .FirstOrDefault();

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Skill Script Payload: Dynamic Code Execution",
                        Description = $"Detected eval/exec usage in '{script.RelativePath}' " +
                            $"of skill '{skill.Name}'.",
                        Remediation = "Remove dynamic code execution (eval, exec, Function constructor).",
                        ServerName = skill.Name,
                        ToolName = script.RelativePath,
                        Evidence = TruncateEvidence(obfuscationMatch?.Value ?? "(matched)"),
                        Confidence = 0.85,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }

            // Scan inline code blocks in markdown body
            ScanMarkdownCodeBlocks(findings, skill);
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    // v3.0.0 (WP10): code blocks come from the document segmenter rather than a
    // fence-matching regex, so every fenced/indented block is covered (not only the
    // previously whitelisted info strings) and fences never interfere with patterns.
    private void ScanMarkdownCodeBlocks(List<Finding> findings, SkillDefinition skill)
    {
        ScanLinkSegments(findings, skill);

        var codeBlocks = SegmentFilter.SegmentsFor(skill, SegmentKind.FencedCode);
        if (codeBlocks.Count == 0) return;

        foreach (var block in codeBlocks)
        {
            var code = StripShebangLine(block.Content);

            foreach (var (pattern, name, severity, description, remediation) in ScriptPatterns)
            {
                if (SafeIsMatch(pattern, code))
                {
                    var match = SafeMatches(pattern, code).FirstOrDefault();

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = severity,
                        Title = $"Skill Inline Code: {name}",
                        Description = $"{description}. Found in markdown code block of skill '{skill.Name}' (line {block.StartLine}).",
                        Remediation = remediation,
                        ServerName = skill.Name,
                        ToolName = "(inline code block)",
                        Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                        Confidence = 0.85,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }

            // Check for hardcoded absolute user paths in code blocks
            if (SafeIsMatch(AbsoluteUserPath(), code))
            {
                var match = SafeMatches(AbsoluteUserPath(), code).FirstOrDefault();

                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = "Skill Inline Code: Hardcoded User Path",
                    Description = $"Skill '{skill.Name}' contains hardcoded absolute user paths " +
                        "in its code blocks. This ties the skill to a specific user/system " +
                        "and may expose directory structure.",
                    Remediation = "Use relative paths or environment variables instead of hardcoded absolute paths.",
                    ServerName = skill.Name,
                    ToolName = "(inline code block)",
                    Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                    Confidence = 0.8,
                    Source = FindingSource.Skill,
                    SkillFilePath = skill.FilePath
                });
            }
        }
    }

    // Link destinations are executable surface too: a link can carry a payload chain
    // in its URL. Only RemoteCodeExecution is meaningful against a URL - the
    // traversal/persistence patterns match innocent paths like /tmp/ and /usr/ in
    // ordinary documentation links (validator S1). Link labels are not scanned here;
    // they remain in the Prose segment.
    private void ScanLinkSegments(List<Finding> findings, SkillDefinition skill)
    {
        foreach (var link in SegmentFilter.SegmentsFor(skill, SegmentKind.Link))
        {
            foreach (var (pattern, name, severity, description, remediation) in ScriptPatterns)
            {
                if (!ReferenceEquals(pattern, RemoteCodeExecution()))
                {
                    continue;
                }

                if (SafeIsMatch(pattern, link.Content))
                {
                    var match = SafeMatches(pattern, link.Content).FirstOrDefault();

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = severity,
                        Title = $"Skill Link Payload: {name}",
                        Description = $"{description}. Found in a link destination of skill '{skill.Name}' (line {link.StartLine}).",
                        Remediation = remediation,
                        ServerName = skill.Name,
                        ToolName = "(link destination)",
                        Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                        Confidence = 0.85,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }
        }
    }

    /// <summary>
    /// Removes a leading shebang line (e.g. <c>#!/usr/bin/env python3</c>) before pattern
    /// matching. Shebang lines are never meaningful evidence for these checks, but their
    /// system paths (<c>/usr/</c>, etc.) collide with legitimate traversal/persistence
    /// pattern fragments.
    /// </summary>
    private static string StripShebangLine(string content)
    {
        if (!content.StartsWith("#!", StringComparison.Ordinal))
        {
            return content;
        }

        var newlineIndex = content.IndexOf('\n');
        return newlineIndex >= 0 ? content[(newlineIndex + 1)..] : string.Empty;
    }

    private static bool SafeIsMatch(Regex pattern, string? input)
    {
        if (string.IsNullOrEmpty(input)) return false;
        try { return pattern.IsMatch(input); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static IEnumerable<Match> SafeMatches(Regex pattern, string? input)
    {
        if (string.IsNullOrEmpty(input)) yield break;
        MatchCollection? matches;
        try { matches = pattern.Matches(input); }
        catch (RegexMatchTimeoutException) { yield break; }
        foreach (Match m in matches) yield return m;
    }

    private static string TruncateEvidence(string evidence) =>
        evidence.Length <= RuleConstants.Limits.MaxEvidenceLength
            ? evidence
            : evidence[..(RuleConstants.Limits.MaxEvidenceLength - 3)] + "...";
}
