// -----------------------------------------------------------------------
// <copyright file="SkillHiddenContentRule.cs" company="Signal Coding Limited">
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
        @"<\s*(script|iframe|object|embed|form|input|link|meta|style)\b[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex DangerousHtmlTag();

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

            // HTML comments (can contain hidden instructions that agents still process)
            CheckPattern(findings, skill, HtmlComment(), content,
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
            CheckPattern(findings, skill, DangerousHtmlTag(), content,
                "Dangerous HTML Tag", Severity.Critical,
                "Detected dangerous HTML tag (script, iframe, object, embed, form) in skill markdown.",
                "Remove dangerous HTML tags from skill markdown.");

            // Data URIs with base64 payloads
            CheckPattern(findings, skill, DataUri(), content,
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

            // Zero-width characters (from shared patterns in InjectionPatterns)
            if (InjectionPatterns.SafeIsMatch(InjectionPatterns.HiddenContent(), content))
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
