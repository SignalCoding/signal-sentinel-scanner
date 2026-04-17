// -----------------------------------------------------------------------
// <copyright file="SigmaPatternRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;
using SignalSentinel.Core.RuleFormats;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// Adapter that evaluates a single loaded <see cref="SigmaRule"/> as an <see cref="IRule"/>.
/// Introduced in v2.2.0 to support Sigma YAML rule import via <c>--sigma-rules</c>.
/// </summary>
/// <remarks>
/// Initialises a new instance of the <see cref="SigmaPatternRule"/> class.
/// </remarks>
/// <param name="rule">Parsed Sigma rule.</param>
public sealed class SigmaPatternRule(SigmaRule rule) : IRule
{
    private readonly SigmaRule _rule = rule ?? throw new ArgumentNullException(nameof(rule));

    /// <inheritdoc />
    public string Id { get; } = $"SIGMA-{rule.Id[..Math.Min(rule.Id.Length, 8)]}";

    /// <inheritdoc />
    public string Name => _rule.Title;

    /// <inheritdoc />
    public string OwaspCode => MapTagToOwasp(_rule.Tags);

    /// <inheritdoc />
    public string Description => _rule.Description;

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var findings = new List<Finding>();

        var targetsMcp = _rule.Product is null
            || string.Equals(_rule.Product, "mcp", StringComparison.OrdinalIgnoreCase);
        var targetsSkill = _rule.Product is null
            || string.Equals(_rule.Product, "skill", StringComparison.OrdinalIgnoreCase);

        if (targetsMcp)
        {
            foreach (var server in context.Servers)
            {
                if (!server.ConnectionSuccessful)
                {
                    continue;
                }

                foreach (var tool in server.Tools)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var description = tool.Description ?? string.Empty;
                    foreach (var pattern in _rule.Patterns)
                    {
                        if (!FieldMatchesToolScope(pattern.FieldName))
                        {
                            continue;
                        }

                        if (Matches(description, pattern))
                        {
                            findings.Add(new Finding
                            {
                                RuleId = Id,
                                OwaspCode = OwaspCode,
                                Severity = _rule.Level,
                                Title = $"Sigma: {_rule.Title}",
                                Description = $"{_rule.Description} Pattern matched field '{pattern.FieldName}' on tool '{tool.Name}'.",
                                Remediation = "Review the tool description against the Sigma rule intent and remediate at source.",
                                ServerName = server.ServerName,
                                ToolName = tool.Name,
                                Evidence = Truncate(pattern.Value),
                                Confidence = 0.8
                            });
                            break; // One finding per tool per rule
                        }
                    }
                }
            }
        }

        if (targetsSkill)
        {
            foreach (var skill in context.Skills)
            {
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var pattern in _rule.Patterns)
                {
                    if (!FieldMatchesSkillScope(pattern.FieldName))
                    {
                        continue;
                    }

                    if (Matches(skill.InstructionsBody, pattern))
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = _rule.Level,
                            Title = $"Sigma: {_rule.Title}",
                            Description = $"{_rule.Description} Pattern matched field '{pattern.FieldName}' in skill '{skill.Name}'.",
                            Remediation = "Review the skill instructions against the Sigma rule intent and remediate at source.",
                            ServerName = skill.Name,
                            Evidence = Truncate(pattern.Value),
                            Confidence = 0.8,
                            Source = FindingSource.Skill,
                            SkillFilePath = skill.FilePath
                        });
                        break;
                    }
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static bool FieldMatchesToolScope(string field) =>
        string.Equals(field, "description", StringComparison.OrdinalIgnoreCase)
        || string.Equals(field, "tool.description", StringComparison.OrdinalIgnoreCase);

    private static bool FieldMatchesSkillScope(string field) =>
        string.Equals(field, "instructions", StringComparison.OrdinalIgnoreCase)
        || string.Equals(field, "skill.instructions", StringComparison.OrdinalIgnoreCase)
        || string.Equals(field, "body", StringComparison.OrdinalIgnoreCase);

    private static bool Matches(string haystack, SigmaPattern pattern) => pattern.MatchType switch
    {
        SigmaMatchType.Equals => string.Equals(haystack, pattern.Value, StringComparison.OrdinalIgnoreCase),
        SigmaMatchType.Contains => haystack.Contains(pattern.Value, StringComparison.OrdinalIgnoreCase),
        SigmaMatchType.StartsWith => haystack.StartsWith(pattern.Value, StringComparison.OrdinalIgnoreCase),
        SigmaMatchType.EndsWith => haystack.EndsWith(pattern.Value, StringComparison.OrdinalIgnoreCase),
        _ => false
    };

    private static string MapTagToOwasp(IReadOnlyList<string> tags)
    {
        foreach (var tag in tags)
        {
            if (tag.StartsWith("owasp.asi", StringComparison.OrdinalIgnoreCase))
            {
                return tag[6..].ToUpperInvariant();
            }
        }
        // Default ASI01 when Sigma tags do not carry an OWASP mapping
        return "ASI01";
    }

    private static string Truncate(string text) =>
        text.Length <= 100 ? text : text[..97] + "...";
}
