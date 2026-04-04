// -----------------------------------------------------------------------
// <copyright file="SkillExfiltrationRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-014: Detects instructions to POST, send, or upload data to external endpoints.
/// Maps to OWASP ASI09 (Sensitive Data Leakage).
/// </summary>
public sealed class SkillExfiltrationRule : IRule
{
    public string Id => RuleConstants.Rules.SkillExfiltration;
    public string Name => "Skill Data Exfiltration Detection";
    public string OwaspCode => OwaspAsiCodes.ASI09;
    public string Description =>
        "Detects instructions to send, POST, or upload data to external endpoints " +
        "in skill instructions and bundled scripts.";
    public bool EnabledByDefault => true;

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Check instructions body
            foreach (var (id, name, pattern, severity, description) in ExfiltrationPatterns.AllPatterns)
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
                        Title = $"Skill Exfiltration: {name}",
                        Description = $"{description}. Found in instructions for skill '{skill.Name}'.",
                        Remediation = "Remove data transmission instructions from the skill. " +
                            "Skills should not instruct the agent to send data to external services.",
                        ServerName = skill.Name,
                        Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                        Confidence = 0.9,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }

            // Also check with the core injection exfiltration pattern
            if (InjectionPatterns.SafeIsMatch(InjectionPatterns.DataExfiltration(), skill.InstructionsBody))
            {
                var match = InjectionPatterns.SafeMatches(InjectionPatterns.DataExfiltration(), skill.InstructionsBody)
                    .FirstOrDefault();

                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Critical,
                    Title = "Skill Exfiltration: External URL Reference",
                    Description = $"Detected reference to external URL or data transmission " +
                        $"in instructions for skill '{skill.Name}'.",
                    Remediation = "Remove references to external URLs from skill instructions.",
                    ServerName = skill.Name,
                    Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                    Confidence = 0.85,
                    Source = FindingSource.Skill,
                    SkillFilePath = skill.FilePath
                });
            }

            // Check bundled scripts
            foreach (var script in skill.Scripts)
            {
                if (script.Content is null) continue;

                foreach (var (id, name, pattern, severity, description) in ExfiltrationPatterns.AllPatterns)
                {
                    if (InjectionPatterns.SafeIsMatch(pattern, script.Content))
                    {
                        var match = InjectionPatterns.SafeMatches(pattern, script.Content)
                            .FirstOrDefault();

                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = severity,
                            Title = $"Skill Script Exfiltration: {name}",
                            Description = $"{description}. Found in bundled script '{script.RelativePath}' " +
                                $"of skill '{skill.Name}'.",
                            Remediation = "Remove data exfiltration patterns from bundled scripts.",
                            ServerName = skill.Name,
                            ToolName = script.RelativePath,
                            Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                            Confidence = 0.9,
                            Source = FindingSource.Skill,
                            SkillFilePath = skill.FilePath
                        });
                    }
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
