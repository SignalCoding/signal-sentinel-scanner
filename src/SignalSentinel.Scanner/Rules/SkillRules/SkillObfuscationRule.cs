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

    // v2.4.0 tightened: conditional-trigger phrasing ("if the user says ...") is normal
    // skill routing and not obfuscation on its own. The pattern now requires a
    // covert-action verb (silently / secretly / bypass / exfiltrate / ignore previous
    // / override / hide / "do not mention") within 120 characters of the trigger phrase.
    // That keeps the high-fidelity signal (conditional + covert intent) while eliminating
    // the v2.3.x false-positive firing on descriptive instructions.
    // v3.0.0 (WP12): the "when the user asks/says/mentions" trigger phrase is removed
    // entirely - it is canonical routing phrasing used across every orchestrator's
    // platform skill descriptions (docs/keyword-rules.md).
    [GeneratedRegex(
        @"\b(?:if\s+the\s+user\s+(?:mentions?|asks?|says?|types?)|only\s+when|only\s+if|trigger(?:ed)?\s+when|activate(?:d)?\s+when|if\s+prompted\s+with)\b[^.\n]{0,120}?\b(?:silently|secretly|covertly|quietly|without\s+(?:asking|telling|notifying|warning|informing|the\s+user\s+knowing)|bypass|exfiltrate|leak|siphon|ignore\s+previous|override|hidden|hide|do\s+not\s+(?:mention|tell|show|display|reveal))\b",
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
                // v3.0.1 (F11): Base64 Decoding and String Reversal need an execution
                // sink in the same unit of code; everything else keeps scanning the
                // whole instructions body.
                if (NeedsExecutionSink(pattern))
                {
                    var gatedEvidence = GatedDocumentEvidence(skill, pattern);
                    if (gatedEvidence is not null)
                    {
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
                            Evidence = TruncateEvidence(gatedEvidence),
                            Confidence = 0.85,
                            Source = FindingSource.Skill,
                            SkillFilePath = skill.FilePath
                        });
                    }

                    continue;
                }

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
                var scriptHasSink = HasExecutionSink(script.Content);

                foreach (var (_, name, pattern, severity, description) in ObfuscationPatterns.AllPatterns)
                {
                    // v3.0.1 (F11): a decode or reversal with no execution sink in the
                    // same script is ordinary data handling, not obfuscation.
                    if (NeedsExecutionSink(pattern) && !scriptHasSink)
                    {
                        continue;
                    }

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

    /// <summary>
    /// v3.0.1 (F11) [migration]: OBFUSC-003 (Base64 Decoding) and OBFUSC-006 (String
    /// Reversal) are only obfuscation when the decoded/reversed value can reach an
    /// execution sink. <c>base64.b64decode</c> on an image and <c>name[::-1]</c> in a
    /// string helper are ordinary code and fired Medium on the corpus.
    /// </summary>
    private static bool NeedsExecutionSink(Regex pattern) =>
        ReferenceEquals(pattern, ObfuscationPatterns.Base64Decoding())
        || ReferenceEquals(pattern, ObfuscationPatterns.StringReversal());

    /// <summary>
    /// Whether a unit of code contains an execution sink: dynamic execution
    /// (eval/exec/Function), character-code assembly, or a dynamic process execution
    /// (SS-016). A fixed literal command such as
    /// <c>subprocess.run(["soffice", "--headless", ...])</c> cannot run a decoded or
    /// reversed string and is not a sink (consistent with F13's severity grading).
    /// </summary>
    private static bool HasExecutionSink(string? unit) =>
        InjectionPatterns.SafeIsMatch(ObfuscationPatterns.DynamicExecution(), unit)
        || InjectionPatterns.SafeIsMatch(ObfuscationPatterns.CharCodeAssembly(), unit)
        || SkillScriptPayloadRule.HasDynamicProcessExecution(unit);

    /// <summary>
    /// The first match of a sink-gated pattern in a document unit that also carries an
    /// execution sink. Each fenced code block is its own unit, as is the remaining
    /// (non-fenced) document text: a decode helper documented in one fence and an
    /// unrelated <c>exec()</c> example in another is not obfuscation.
    /// </summary>
    private static string? GatedDocumentEvidence(SkillDefinition skill, Regex pattern)
    {
        foreach (var unit in DocumentUnits(skill))
        {
            if (!InjectionPatterns.SafeIsMatch(pattern, unit) || !HasExecutionSink(unit))
            {
                continue;
            }

            var match = InjectionPatterns.SafeMatches(pattern, unit).FirstOrDefault();
            if (match is not null)
            {
                return match.Value;
            }
        }

        return null;
    }

    private static IEnumerable<string> DocumentUnits(SkillDefinition skill)
    {
        foreach (var block in SegmentFilter.SegmentsFor(skill, SegmentKind.FencedCode))
        {
            yield return block.Content;
        }

        yield return SegmentFilter.TextFor(skill, SegmentKind.All & ~SegmentKind.FencedCode);
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
