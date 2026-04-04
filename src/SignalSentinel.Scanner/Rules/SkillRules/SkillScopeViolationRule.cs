// -----------------------------------------------------------------------
// <copyright file="SkillScopeViolationRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-012: Detects mismatch between a skill's stated purpose (frontmatter) and
/// its actual instructions (body). A skill that says it "formats code" but instructs
/// the agent to access the filesystem or make network requests is a scope violation.
/// Maps to OWASP ASI02 (Tool Misuse and Exploitation).
/// </summary>
public sealed partial class SkillScopeViolationRule : IRule
{
    public string Id => RuleConstants.Rules.SkillScopeViolation;
    public string Name => "Skill Scope Violation Detection";
    public string OwaspCode => OwaspAsiCodes.ASI02;
    public string Description =>
        "Detects mismatch between a skill's stated purpose and its actual instructions, " +
        "indicating the skill may perform actions beyond its described scope.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(
        @"\b(read_file|write_file|readFile|writeFile|fs\.|filesystem|file\s+system|open\s+file|create\s+file|delete\s+file|mkdir|rmdir)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex FileSystemCapability();

    [GeneratedRegex(
        @"\b(http|https|fetch|curl|wget|request|api\s+call|endpoint|webhook|socket)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex NetworkCapability();

    [GeneratedRegex(
        @"\b(exec|spawn|shell|subprocess|child_process|system\(|popen|Process\.Start|os\.system|sh\s+-c|bash\s+-c|cmd\s+/c|powershell\s+-)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex ShellCapability();

    [GeneratedRegex(
        @"\b(python3?\s+-c|bash\s+-c|sh\s+-c|node\s+-e|ruby\s+-e|perl\s+-e|powershell\s+-Command)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex InlineCodeExecution();

    [GeneratedRegex(
        @"\b(format|lint|style|beautif|indent|prettif|syntax|highlight|color|theme|render|display|convert|transform)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex BenignPurpose();

    private static readonly (Regex Pattern, string Capability, Severity Severity)[] DangerousCapabilities =
    [
        (FileSystemCapability(), "filesystem access", Severity.High),
        (NetworkCapability(), "network access", Severity.High),
        (ShellCapability(), "shell/command execution", Severity.Critical),
        (InlineCodeExecution(), "inline code execution (e.g. python3 -c)", Severity.High),
    ];

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var statedPurpose = skill.Description ?? skill.Name;
            var isBenignPurpose = SafeIsMatch(BenignPurpose(), statedPurpose);

            foreach (var (pattern, capability, severity) in DangerousCapabilities)
            {
                var purposeHasCapability = SafeIsMatch(pattern, statedPurpose);
                var bodyHasCapability = SafeIsMatch(pattern, skill.InstructionsBody);

                // Scope violation: body uses capability not mentioned in purpose
                if (bodyHasCapability && !purposeHasCapability)
                {
                    var effectiveSeverity = isBenignPurpose ? severity : Severity.Medium;

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = effectiveSeverity,
                        Title = $"Skill Scope Violation: Undeclared {capability}",
                        Description = $"Skill '{skill.Name}' is described as '{Truncate(statedPurpose, 100)}' " +
                            $"but its instructions reference {capability} which is not part of its stated purpose.",
                        Remediation = $"Either update the skill description to include {capability}, " +
                            $"or remove the {capability} instructions if they are not needed.",
                        ServerName = skill.Name,
                        Evidence = capability,
                        Confidence = isBenignPurpose ? 0.85 : 0.7,
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

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..(maxLength - 3)] + "...";
}
