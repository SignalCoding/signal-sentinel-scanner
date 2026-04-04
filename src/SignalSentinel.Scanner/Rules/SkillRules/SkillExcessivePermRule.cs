// -----------------------------------------------------------------------
// <copyright file="SkillExcessivePermRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-017: Detects skills requesting filesystem, network, or shell access beyond their stated scope.
/// Also flags dangerous context settings like "context: full" combined with excessive capabilities.
/// Maps to OWASP ASI02 (Tool Misuse and Exploitation).
/// </summary>
public sealed partial class SkillExcessivePermRule : IRule
{
    public string Id => RuleConstants.Rules.SkillExcessivePermissions;
    public string Name => "Skill Excessive Permissions Detection";
    public string OwaspCode => OwaspAsiCodes.ASI02;
    public string Description =>
        "Detects skills requesting excessive filesystem, network, or shell access, " +
        "and flags dangerous context/agent settings in frontmatter.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(
        @"\b(read\s+any\s+file|write\s+any\s+file|access\s+all\s+files|full\s+filesystem|entire\s+filesystem|read\s+all\s+directories|recursive\s+access|unrestricted\s+access)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex UnrestrictedFilesystem();

    [GeneratedRegex(
        @"\b(any\s+url|any\s+endpoint|any\s+server|any\s+host|any\s+domain|unrestricted\s+network|full\s+network|internet\s+access|all\s+ports)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex UnrestrictedNetwork();

    [GeneratedRegex(
        @"\b(run\s+any\s+command|execute\s+any|arbitrary\s+command|arbitrary\s+code|unrestricted\s+shell|full\s+shell|root\s+access|admin\s+access|sudo|as\s+root)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex UnrestrictedShell();

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Check frontmatter: dangerous context settings
            if (skill.Context is not null)
            {
                var contextLower = skill.Context.ToLowerInvariant();
                if (contextLower is "full" or "fork")
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = $"Skill Excessive Permissions: Dangerous Context Setting ({skill.Context})",
                        Description = $"Skill '{skill.Name}' uses 'context: {skill.Context}' which grants " +
                            "broad access to the agent's conversation context.",
                        Remediation = "Use a more restrictive context setting unless full context access " +
                            "is absolutely required for the skill's functionality.",
                        ServerName = skill.Name,
                        Evidence = $"context: {skill.Context}",
                        Confidence = 0.8,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }

            // Check frontmatter: agent override
            if (skill.Agent is not null)
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = "Skill Excessive Permissions: Custom Agent Override",
                    Description = $"Skill '{skill.Name}' specifies a custom agent configuration " +
                        "which could bypass default safety controls.",
                    Remediation = "Review the custom agent configuration and ensure it maintains " +
                        "appropriate safety boundaries.",
                    ServerName = skill.Name,
                    Evidence = $"agent: {Truncate(skill.Agent, 50)}",
                    Confidence = 0.7,
                    Source = FindingSource.Skill,
                    SkillFilePath = skill.FilePath
                });
            }

            // Check frontmatter: missing metadata
            if (string.IsNullOrWhiteSpace(skill.Description))
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Low,
                    Title = "Skill Excessive Permissions: Missing Description",
                    Description = $"Skill '{skill.Name}' has no description in frontmatter. " +
                        "Missing metadata reduces transparency (opacity equals risk).",
                    Remediation = "Add a clear description to the skill's YAML frontmatter " +
                        "explaining what the skill does.",
                    ServerName = skill.Name,
                    Confidence = 0.95,
                    Source = FindingSource.Skill,
                    SkillFilePath = skill.FilePath
                });
            }

            // Check instructions for excessive capability requests
            CheckPattern(findings, skill, UnrestrictedFilesystem(), "Unrestricted Filesystem Access",
                "requests unrestricted filesystem access",
                "Restrict filesystem access to specific directories needed by the skill.");

            CheckPattern(findings, skill, UnrestrictedNetwork(), "Unrestricted Network Access",
                "requests unrestricted network access",
                "Restrict network access to specific endpoints needed by the skill.");

            CheckPattern(findings, skill, UnrestrictedShell(), "Unrestricted Shell Access",
                "requests unrestricted shell/command execution",
                "Avoid requesting arbitrary command execution. Specify the exact commands needed.");
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private void CheckPattern(
        List<Finding> findings,
        SkillDefinition skill,
        Regex pattern,
        string patternName,
        string verb,
        string remediation)
    {
        if (!SafeIsMatch(pattern, skill.InstructionsBody)) return;

        var match = SafeMatches(pattern, skill.InstructionsBody).FirstOrDefault();

        findings.Add(new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = Severity.High,
            Title = $"Skill Excessive Permissions: {patternName}",
            Description = $"Skill '{skill.Name}' {verb} in its instructions.",
            Remediation = remediation,
            ServerName = skill.Name,
            Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
            Confidence = 0.85,
            Source = FindingSource.Skill,
            SkillFilePath = skill.FilePath
        });
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

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..(maxLength - 3)] + "...";

    private static string TruncateEvidence(string evidence) =>
        evidence.Length <= RuleConstants.Limits.MaxEvidenceLength
            ? evidence
            : evidence[..(RuleConstants.Limits.MaxEvidenceLength - 3)] + "...";
}
