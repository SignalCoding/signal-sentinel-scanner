// -----------------------------------------------------------------------
// <copyright file="SkillCredentialAccessRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-013: Detects references to API keys, tokens, SSH keys, and environment
/// variables containing credentials within skill instructions and bundled scripts.
/// Maps to OWASP ASI03 (Identity and Privilege Abuse).
/// </summary>
public sealed class SkillCredentialAccessRule : IRule
{
    public string Id => RuleConstants.Rules.SkillCredentialAccess;
    public string Name => "Skill Credential Access Detection";
    public string OwaspCode => OwaspAsiCodes.ASI03;
    public string Description =>
        "Detects references to API keys, tokens, SSH keys, and credential environment " +
        "variables in skill instructions and bundled scripts.";
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
            foreach (var (id, name, pattern, severity, description) in CredentialPatterns.AllPatterns)
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
                        Title = $"Skill Credential Access: {name}",
                        Description = $"{description}. Found in instructions for skill '{skill.Name}'.",
                        Remediation = "Remove credential references from skill instructions. " +
                            "Skills should never instruct the agent to access API keys, tokens, or secrets.",
                        ServerName = skill.Name,
                        Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
                        Confidence = 0.9,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }

            // Check bundled scripts
            foreach (var script in skill.Scripts)
            {
                if (script.Content is null) continue;

                foreach (var (id, name, pattern, severity, description) in CredentialPatterns.AllPatterns)
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
                            Title = $"Skill Script Credential Access: {name}",
                            Description = $"{description}. Found in bundled script '{script.RelativePath}' " +
                                $"of skill '{skill.Name}'.",
                            Remediation = "Remove credential access from bundled scripts. " +
                                "Use secure secret management instead of direct credential references.",
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
