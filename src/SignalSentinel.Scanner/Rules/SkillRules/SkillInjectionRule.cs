// -----------------------------------------------------------------------
// <copyright file="SkillInjectionRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-011: Detects prompt injection patterns in SKILL.md instruction bodies.
/// Maps to OWASP ASI01 (Agent Goal Hijack).
/// Shares detection patterns with MCP tool poisoning but applied to skill instructions.
/// </summary>
public sealed class SkillInjectionRule : IRule
{
    public string Id => RuleConstants.Rules.SkillInjection;
    public string Name => "Skill Prompt Injection Detection";
    public string OwaspCode => OwaspAsiCodes.ASI01;
    public string Description =>
        "Detects prompt injection patterns hidden in Agent Skill instructions " +
        "that could hijack agent behaviour beyond the skill's stated purpose.";
    public bool EnabledByDefault => true;

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var pattern in InjectionPatterns.AllPatterns)
            {
                if (InjectionPatterns.SafeIsMatch(pattern.Pattern, skill.InstructionsBody))
                {
                    var match = InjectionPatterns.SafeMatches(pattern.Pattern, skill.InstructionsBody)
                        .FirstOrDefault();

                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = pattern.Severity,
                        Title = $"Skill Injection: {pattern.Name}",
                        Description = $"{pattern.Description}. Pattern '{pattern.Id}' matched in skill instructions for '{skill.Name}'.",
                        Remediation = "Review the skill instructions and remove any directive language, " +
                            "injection patterns, or content that attempts to override agent behaviour.",
                        ServerName = skill.Name,
                        ToolName = null,
                        Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                        Confidence = 0.85,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static string TruncateEvidence(string evidence) =>
        evidence.Length <= RuleConstants.Limits.MaxEvidenceLength
            ? evidence
            : evidence[..(RuleConstants.Limits.MaxEvidenceLength - 3)] + "...";
}
