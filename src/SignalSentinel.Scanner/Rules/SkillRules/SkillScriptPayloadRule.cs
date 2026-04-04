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

    [GeneratedRegex(
        @"(curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh|Invoke-WebRequest.*\|\s*Invoke-Expression|iwr.*\|\s*iex|curl\s+.*-o\s+\S+.*chmod\s+\+x)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex RemoteCodeExecution();

    [GeneratedRegex(
        @"(crontab|cron\.d|systemctl\s+enable|schtasks\s+/create|Register-ScheduledTask|\.bashrc|\.zshrc|\.bash_profile|\.profile|shell:startup|autostart|launchctl\s+load|launchd)",
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

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var script in skill.Scripts)
            {
                if (script.Content is null) continue;

                foreach (var (pattern, name, severity, description, remediation) in ScriptPatterns)
                {
                    if (SafeIsMatch(pattern, script.Content))
                    {
                        var match = SafeMatches(pattern, script.Content).FirstOrDefault();

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
                if (InjectionPatterns.SafeIsMatch(ObfuscationPatterns.DynamicExecution(), script.Content))
                {
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
                        Confidence = 0.85,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
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
