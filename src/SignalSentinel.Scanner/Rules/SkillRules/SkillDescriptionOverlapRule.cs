// -----------------------------------------------------------------------
// <copyright file="SkillDescriptionOverlapRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Globalization;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-037: Two differently named skills whose descriptions are near-duplicates.
/// Maps to OWASP ASI01 (Agent Goal Hijack).
/// </summary>
/// <remarks>
/// Agents pick a skill by matching the user's request against skill descriptions. A
/// malicious skill that copies a trusted skill's description competes for the same
/// requests and wins some of them. Token-set Jaccard similarity over the normalised
/// description is cheap, order-insensitive, and robust to small edits. Threshold 0.80.
/// </remarks>
public sealed class SkillDescriptionOverlapRule : IRule
{
    /// <summary>Jaccard similarity at or above which two descriptions count as duplicates.</summary>
    public const double Threshold = 0.80;

    private const int MinTokens = 5;
    private const int MaxSkillsCompared = 2_000;

    private static readonly HashSet<string> StopWords = new(StringComparer.Ordinal)
    {
        "the", "and", "for", "with", "that", "this", "from", "into", "your", "you", "are", "can",
        "use", "using", "used", "when", "then", "than", "them", "they", "will", "which", "what",
        "how", "any", "all", "not", "but", "its", "has", "have", "was", "were", "been", "being",
        "skill", "agent", "tool", "tools", "helps", "help", "allows", "allow", "lets", "let",
        "provides", "provide", "about", "also", "each", "one", "two", "via", "per", "should",
        // Marketplace trigger boilerplate ("Use this skill whenever the user asks to ...").
        "user", "users", "asks", "asked", "asking", "wants", "want", "needs", "need", "whenever",
        "mentions", "mention", "trigger", "triggers", "triggered", "proactively", "shares",
        "changes", "invoke", "invoked", "request", "working"
    };

    /// <inheritdoc />
    public string Id => RuleConstants.Rules.SkillDescriptionOverlap;

    /// <inheritdoc />
    public string Name => "Cross-Skill Description Overlap";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description =>
        "Flags pairs of differently named skills whose descriptions are near-duplicates, a pattern used to hijack skill selection.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST04];

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        var candidates = context.Skills
            .Take(MaxSkillsCompared)
            .Select(s => (Skill: s, Tokens: Tokenise(s.Description)))
            .Where(x => x.Tokens.Count >= MinTokens)
            .ToList();

        for (var i = 0; i < candidates.Count; i++)
        {
            for (var j = i + 1; j < candidates.Count; j++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var (a, ta) = candidates[i];
                var (b, tb) = candidates[j];

                if (string.Equals(a.CanonicalSkillName, b.CanonicalSkillName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(a.FilePath, b.FilePath, StringComparison.OrdinalIgnoreCase))
                {
                    // Same skill installed twice (e.g. personal + project copy) is a
                    // duplicate-install concern, not description hijacking.
                    continue;
                }

                var score = Jaccard(ta, tb);
                if (score < Threshold)
                {
                    continue;
                }

                var scoreText = score.ToString("0.00", CultureInfo.InvariantCulture);
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = $"Skill Descriptions Nearly Identical: '{a.CanonicalSkillName}' and '{b.CanonicalSkillName}'",
                    Description =
                        $"Skills '{a.CanonicalSkillName}' ({a.FilePath}) and '{b.CanonicalSkillName}' ({b.FilePath}) have different names but descriptions with Jaccard similarity {scoreText}. " +
                        "Agents route requests by description, so these two compete for the same requests. One may be impersonating the other.",
                    Remediation =
                        "Confirm both skills are yours and intentionally overlapping. Otherwise remove the one you did not install deliberately and check where it came from.",
                    ServerName = a.Name,
                    Evidence = DescriptionScan.Truncate($"{a.CanonicalSkillName} ~ {b.CanonicalSkillName} (jaccard={scoreText})"),
                    Confidence = score >= 0.95 ? 0.9 : 0.75,
                    Source = FindingSource.Skill,
                    SkillFilePath = a.FilePath
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    /// <summary>
    /// Lower-cases, splits on non-alphanumerics, drops short tokens and stop words.
    /// </summary>
    internal static HashSet<string> Tokenise(string? text)
    {
        var tokens = new HashSet<string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(text))
        {
            return tokens;
        }

        var current = new System.Text.StringBuilder();
        foreach (var ch in text)
        {
            if (char.IsLetterOrDigit(ch))
            {
                current.Append(char.ToLowerInvariant(ch));
            }
            else if (current.Length > 0)
            {
                Flush(current, tokens);
            }
        }

        Flush(current, tokens);
        return tokens;
    }

    private static void Flush(System.Text.StringBuilder current, HashSet<string> tokens)
    {
        if (current.Length >= 3)
        {
            var token = current.ToString();
            if (!StopWords.Contains(token))
            {
                tokens.Add(token);
            }
        }

        current.Clear();
    }

    internal static double Jaccard(HashSet<string> a, HashSet<string> b)
    {
        if (a.Count == 0 && b.Count == 0)
        {
            return 0;
        }

        var intersection = a.Count(b.Contains);
        var union = a.Count + b.Count - intersection;
        return union == 0 ? 0 : (double)intersection / union;
    }
}
