// -----------------------------------------------------------------------
// <copyright file="SkillObfuscationRule.cs" company="Signal Coding Limited">
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
/// SS-015: Detects zero-width characters, Unicode tricks, conditional triggers,
/// and other obfuscation techniques in skill instructions.
/// Maps to OWASP ASI01 (Agent Goal Hijack).
/// </summary>
public sealed partial class SkillObfuscationRule : IRule
{
    public string Id => RuleConstants.Rules.SkillObfuscation;
    public string Name => "Skill Obfuscation Detection";
    public string OwaspCode => OwaspAsiCodes.ASI01;
    public string Description =>
        "Detects zero-width characters, Unicode tricks, conditional triggers, " +
        "and other obfuscation techniques in skill instructions and scripts.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(
        @"\b(if\s+the\s+user\s+(mentions?|asks?|says?|types?)|when\s+the\s+user\s+(mentions?|asks?|says?)|only\s+when|only\s+if|trigger\s+when|activate\s+when|if\s+prompted\s+with)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex ConditionalTrigger();

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Check shared obfuscation patterns
            foreach (var (id, name, pattern, severity, description) in ObfuscationPatterns.AllPatterns)
            {
                if (InjectionPatterns.SafeIsMatch(pattern, skill.InstructionsBody))
                {
                    var match = InjectionPatterns.SafeMatches(pattern, skill.InstructionsBody)
                        .FirstOrDefault();

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = severity,
                        Title = $"Skill Obfuscation: {name}",
                        Description = $"{description}. Found in instructions for skill '{skill.Name}'.",
                        Remediation = "Remove obfuscated content from skill instructions. " +
                            "All instructions should be in plain, readable text.",
                        ServerName = skill.Name,
                        Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                        Confidence = 0.85,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }

            // Check conditional triggers (skill-specific)
            if (SafeIsMatch(ConditionalTrigger(), skill.InstructionsBody))
            {
                var match = SafeMatches(ConditionalTrigger(), skill.InstructionsBody)
                    .FirstOrDefault();

                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.High,
                    Title = "Skill Obfuscation: Conditional Trigger",
                    Description = $"Skill '{skill.Name}' contains conditional trigger instructions " +
                        "that only activate under specific circumstances, which may evade casual review.",
                    Remediation = "Review conditional instructions carefully. " +
                        "Legitimate skills should not contain hidden conditional triggers.",
                    ServerName = skill.Name,
                    Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                    Confidence = 0.75,
                    Source = FindingSource.Skill,
                    SkillFilePath = skill.FilePath
                });
            }

            // Check bundled scripts for obfuscation
            foreach (var script in skill.Scripts)
            {
                if (script.Content is null) continue;

                foreach (var (id, name, pattern, severity, description) in ObfuscationPatterns.AllPatterns)
                {
                    if (InjectionPatterns.SafeIsMatch(pattern, script.Content))
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = severity,
                            Title = $"Skill Script Obfuscation: {name}",
                            Description = $"{description}. Found in script '{script.RelativePath}' " +
                                $"of skill '{skill.Name}'.",
                            Remediation = "Remove obfuscation from bundled scripts. " +
                                "All code should be clear and readable.",
                            ServerName = skill.Name,
                            ToolName = script.RelativePath,
                            Confidence = 0.85,
                            Source = FindingSource.Skill,
                            SkillFilePath = skill.FilePath
                        });
                    }
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
