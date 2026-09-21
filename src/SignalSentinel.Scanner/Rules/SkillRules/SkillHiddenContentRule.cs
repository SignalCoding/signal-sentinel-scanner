// -----------------------------------------------------------------------
// <copyright file="SkillHiddenContentRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-018: Detects HTML comments, base64 blocks, encoded payloads, and other
/// hidden content in SKILL.md markdown that could contain concealed instructions.
/// Maps to OWASP ASI01 (Agent Goal Hijack).
/// </summary>
public sealed partial class SkillHiddenContentRule : IRule
{
    public string Id => RuleConstants.Rules.SkillHiddenContent;
    public string Name => "Skill Hidden Content Detection";
    public string OwaspCode => OwaspAsiCodes.ASI01;
    public string Description =>
        "Detects HTML comments, base64 blocks, encoded payloads, and other hidden " +
        "content in skill markdown that could conceal malicious instructions.";
    public bool EnabledByDefault => true;

    /// <summary>
    /// v3.0.1 (F3): the markup checks (HTML comment, dangerous tag, meta refresh, data
    /// URI) evaluate prose, raw HTML and frontmatter only. A <c>&lt;script src=...&gt;</c>
    /// or <c>&lt;!-- ... --&gt;</c> inside a ```html documentation fence is an example, not
    /// concealed content - the v3.0.0 rule scanned <c>RawContent</c> and graded those
    /// Critical. The two fence-shaped checks (Suspicious Code Block, Large Base64
    /// Block) keep reading raw content because that is where their signal lives, as
    /// does the invisible-character check.
    /// </summary>
    public SegmentKind ApplicableSegments =>
        SegmentKind.Prose | SegmentKind.HtmlBlock | SegmentKind.Frontmatter;

    [GeneratedRegex(
        @"<!--[\s\S]*?-->",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex HtmlComment();

    [GeneratedRegex(
        @"```\s*(base64|encoded|hidden|secret)\b[\s\S]*?```",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex SuspiciousCodeBlock();

    [GeneratedRegex(
        @"<\s*(script|iframe|object|embed|form|input|link|style)\b[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex DangerousHtmlTag();

    // v2.5.1: bare "meta" was in the dangerous-tag alternation above, flagging every
    // ordinary <meta charset="UTF-8"> or <meta name="viewport" ...> as Critical - a
    // real-world review found this on markdown that had simply pasted an HTML head
    // snippet as documentation. A <meta> tag is only a genuine hidden-redirect vector
    // when it carries http-equiv (e.g. http-equiv="refresh"), so that is now checked
    // separately and requires the attribute.
    [GeneratedRegex(
        @"<\s*meta\b[^>]*\bhttp-equiv\s*=",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex DangerousMetaRefresh();

    [GeneratedRegex(
        @"data:(?:text|application)/[^;]+;base64,[A-Za-z0-9+/=]{50,}",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex DataUri();

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var content = skill.RawContent;

            // v3.0.1 (F3): markup lives in prose/HTML/frontmatter, never in a code fence.
            var markup = SegmentFilter.TextFor(skill, ApplicableSegments);

            // HTML comments (can contain hidden instructions that agents still process)
            CheckPattern(findings, skill, HtmlComment(), markup,
                "HTML Comment", Severity.High,
                "Detected HTML comment in skill markdown. AI agents may still process comment content, " +
                    "making this a vector for hidden instruction injection.",
                "Remove HTML comments or replace with visible documentation.");

            // Suspicious code blocks
            CheckPattern(findings, skill, SuspiciousCodeBlock(), content,
                "Suspicious Code Block", Severity.High,
                "Detected code block labelled as base64, encoded, hidden, or secret content.",
                "Remove suspicious code blocks. Use clear, readable content only.");

            // Dangerous HTML tags (markdown can contain HTML)
            CheckPattern(findings, skill, DangerousHtmlTag(), markup,
                "Dangerous HTML Tag", Severity.Critical,
                "Detected dangerous HTML tag (script, iframe, object, embed, form) in skill markdown.",
                "Remove dangerous HTML tags from skill markdown.");

            // <meta http-equiv> (redirect/refresh vectors) - see DangerousMetaRefresh().
            CheckPattern(findings, skill, DangerousMetaRefresh(), markup,
                "Meta Refresh/Redirect Tag", Severity.Critical,
                "Detected a <meta http-equiv> tag, commonly used for hidden page redirects (meta refresh).",
                "Remove meta http-equiv redirect tags from skill markdown.");

            // Data URIs with base64 payloads
            CheckPattern(findings, skill, DataUri(), markup,
                "Data URI Payload", Severity.High,
                "Detected data URI with base64-encoded payload that could contain hidden content.",
                "Remove data URIs from skill content.");

            // Large base64 blocks (from shared patterns)
            if (InjectionPatterns.SafeIsMatch(InjectionPatterns.Base64Payload(), content))
            {
                var matches = InjectionPatterns.SafeMatches(InjectionPatterns.Base64Payload(), content).ToList();
                // Only flag if there's a suspiciously large base64 block
                var largeBlocks = matches.Where(m => m.Length > 100).ToList();
                if (largeBlocks.Count > 0)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Medium,
                        Title = "Skill Hidden Content: Large Base64 Block",
                        Description = $"Detected {largeBlocks.Count} large base64-encoded block(s) " +
                            $"in skill '{skill.Name}' that could contain hidden instructions.",
                        Remediation = "Review base64 content and decode it to verify it is not malicious.",
                        ServerName = skill.Name,
                        Evidence = $"{largeBlocks.Count} block(s), largest: {largeBlocks.Max(m => m.Length)} chars",
                        Confidence = 0.7,
                        Source = FindingSource.Skill,
                        SkillFilePath = skill.FilePath
                    });
                }
            }

            // v3.0.1 (F2): invisible characters only. This finding used to test
            // InjectionPatterns.HiddenContent(), whose alternation also matches
            // "<!-- ... -->", so it fired High "Zero-Width Characters" on three
            // real skills that contain no invisible character at all. It now uses the
            // zero-width cluster / BiDi override / NUL patterns, and reports the code
            // points rather than the (invisible, copy-paste-hostile) characters.
            var invisibleEvidence = InvisibleCharacterEvidence(content);
            if (invisibleEvidence is not null)
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.High,
                    Title = "Skill Hidden Content: Zero-Width Characters",
                    Description = $"Detected zero-width or invisible Unicode characters in skill '{skill.Name}' " +
                        "that could hide malicious instructions.",
                    Remediation = "Remove all zero-width and invisible Unicode characters from skill content.",
                    ServerName = skill.Name,
                    Evidence = TruncateEvidence(invisibleEvidence),
                    Confidence = 0.9,
                    Source = FindingSource.Skill,
                    SkillFilePath = skill.FilePath
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static void CheckPattern(
        List<Finding> findings,
        SkillDefinition skill,
        Regex pattern,
        string content,
        string patternName,
        Severity severity,
        string description,
        string remediation)
    {
        if (!SafeIsMatch(pattern, content)) return;

        var match = SafeMatches(pattern, content).FirstOrDefault();

        findings.Add(new Finding
        {
            RuleId = RuleConstants.Rules.SkillHiddenContent,
            OwaspCode = OwaspAsiCodes.ASI01,
            Severity = severity,
            Title = $"Skill Hidden Content: {patternName}",
            Description = $"{description} Found in skill '{skill.Name}'.",
            Remediation = remediation,
            ServerName = skill.Name,
            Evidence = TruncateEvidence(match?.Value ?? "(matched)"),
            Confidence = 0.85,
            Source = FindingSource.Skill,
            SkillFilePath = skill.FilePath
        });
    }

    /// <summary>
    /// v3.0.1 (F2): the code points of every invisible character in the content -
    /// clusters of two or more zero-width characters, BiDi overrides, and NUL - in the
    /// form <c>U+200B x3</c>. Returns <see langword="null"/> when the content carries
    /// none. A lone U+200D (emoji ZWJ sequence) is not a cluster and is not reported.
    /// </summary>
    private static string? InvisibleCharacterEvidence(string content)
    {
        var counts = new SortedDictionary<int, int>();

        foreach (var match in SafeMatches(ObfuscationPatterns.ZeroWidthCharClusters(), content))
        {
            CountCharacters(counts, match.Value);
        }

        foreach (var match in SafeMatches(ObfuscationPatterns.BidiOverrides(), content))
        {
            CountCharacters(counts, match.Value);
        }

        foreach (var character in content)
        {
            if (character == '\0')
            {
                counts[0] = counts.TryGetValue(0, out var nulls) ? nulls + 1 : 1;
            }
        }

        if (counts.Count == 0)
        {
            return null;
        }

        var builder = new StringBuilder();
        foreach (var (codePoint, count) in counts)
        {
            if (builder.Length > 0)
            {
                builder.Append(", ");
            }

            builder.Append("U+")
                .Append(codePoint.ToString("X4", CultureInfo.InvariantCulture))
                .Append(" x")
                .Append(count.ToString(CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }

    private static void CountCharacters(SortedDictionary<int, int> counts, string value)
    {
        foreach (var character in value)
        {
            counts[character] = counts.TryGetValue(character, out var existing) ? existing + 1 : 1;
        }
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
