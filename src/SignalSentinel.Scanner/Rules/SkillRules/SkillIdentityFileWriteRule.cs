// -----------------------------------------------------------------------
// <copyright file="SkillIdentityFileWriteRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-028 (v2.4.1, G12b): flags skills whose instructions or bundled scripts write
/// to agent identity/memory files (<c>AGENTS.md</c>, <c>CLAUDE.md</c>,
/// <c>MEMORY.md</c>, <c>SOUL.md</c>). This was the session-persistent backdooring
/// vector used by the ClawHavoc campaign (Jan-Feb 2026, 1,184 malicious skills):
/// a skill writes malicious instructions directly into these files so they
/// survive and re-inject on every future session, not just the one where the
/// malicious skill ran. Maps to OWASP AST03 (Over-Privileged Skills) - a skill
/// legitimately reading its own scratch files has no business writing to the
/// orchestrator's persistent identity/memory surface.
/// </summary>
public sealed partial class SkillIdentityFileWriteRule : IRule
{
    public string Id => RuleConstants.Rules.SkillIdentityFileWrite;
    public string Name => "Skill Identity/Memory File Write Access";
    public string OwaspCode => OwaspAsiCodes.ASI02;
    public string Description =>
        "Detects skills whose instructions or bundled scripts write to agent " +
        "identity/memory files (AGENTS.md, CLAUDE.md, MEMORY.md, SOUL.md), a " +
        "session-persistent backdooring technique.";
    public bool EnabledByDefault => true;
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST03];

    private const string IdentityFilePattern = @"(AGENTS\.md|CLAUDE\.md|MEMORY\.md|SOUL\.md)";

    // Natural-language write intent in the skill's instructions: a write/edit verb
    // followed (within a short span) by one of the identity filenames.
    [GeneratedRegex(
        @"\b(write|writes|writing|append|appends|appending|edit|edits|editing|modify|modifies|modifying|update|updates|updating|overwrite|overwrites|overwriting|create|creates|creating|delete|deletes|deleting)\b" +
        @"[^.\n]{0,40}\b" + IdentityFilePattern,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex WriteIntentPattern();

    // Code-level write operations against an identity file: Python open(...,"w"/"a"),
    // shell redirection (> / >>), or in-place editors (sed -i).
    [GeneratedRegex(
        @"(open\s*\([^)]*" + IdentityFilePattern + @"[^)]*,\s*[""'][wa]|" +
        @">{1,2}\s*[^\n]{0,20}" + IdentityFilePattern + "|" +
        @"sed\s+-i[^\n]{0,60}" + IdentityFilePattern + ")",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex ScriptWritePattern();

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var evidence = SafeMatch(WriteIntentPattern(), skill.InstructionsBody);
            var evidenceSource = "instructions";

            if (evidence is null)
            {
                foreach (var script in skill.Scripts)
                {
                    var scriptMatch = SafeMatch(ScriptWritePattern(), script.Content);
                    if (scriptMatch is not null)
                    {
                        evidence = scriptMatch;
                        evidenceSource = $"script: {script.RelativePath}";
                        break;
                    }
                }
            }

            if (evidence is null)
            {
                continue;
            }

            // v2.5.0 (G15d): if the skill's own frontmatter declares this exact
            // file under deny_write, the write is a direct self-contradiction -
            // not just an undocumented capability, but one the skill author
            // explicitly promised not to exercise. Escalate to Critical.
            var matchedFile = Regex.Match(evidence, IdentityFilePattern, RegexOptions.IgnoreCase).Value;
            var contradictsDenyWrite = matchedFile.Length > 0 && skill.DenyWrite.Any(
                denied => denied.Contains(matchedFile, StringComparison.OrdinalIgnoreCase));

            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                AstCodes = AstCodes,
                Severity = contradictsDenyWrite ? Severity.Critical : Severity.High,
                Title = contradictsDenyWrite
                    ? $"Skill Contradicts Its Own deny_write Declaration: {skill.Name}"
                    : $"Skill Writes to Identity/Memory File: {skill.Name}",
                Description = contradictsDenyWrite
                    ? $"Skill '{skill.Name}' ({evidenceSource}) writes to '{matchedFile}', despite " +
                      $"its own frontmatter declaring '{matchedFile}' under 'deny_write'. A skill " +
                      "that writes to a file it explicitly promised not to touch is either " +
                      "badly broken or deliberately misrepresenting its behaviour."
                    : $"Skill '{skill.Name}' ({evidenceSource}) writes to an agent " +
                      "identity/memory file (AGENTS.md, CLAUDE.md, MEMORY.md, or " +
                      "SOUL.md). Writing to these files lets a skill's influence " +
                      "persist across sessions long after the skill itself has run - " +
                      "the documented technique behind the ClawHavoc malicious-skill " +
                      "campaign (Jan-Feb 2026).",
                Remediation = contradictsDenyWrite
                    ? $"Remove the write to '{matchedFile}', or remove the false 'deny_write' " +
                      "declaration if the skill genuinely needs write access - do not ship a " +
                      "permission promise the skill itself violates."
                    : "Skills should not write to the orchestrator's identity/memory " +
                      "files. If a skill legitimately needs to persist state, use a " +
                      "dedicated scratch file under its own skill directory instead. " +
                      "If this skill is explicitly a memory-management utility, " +
                      "document that scope clearly and review the write path.",
                ServerName = skill.Name,
                Evidence = TruncateEvidence(evidence),
                Confidence = contradictsDenyWrite ? 0.95 : 0.85,
                Source = FindingSource.Skill,
                SkillFilePath = skill.FilePath
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static string? SafeMatch(Regex pattern, string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return null;
        }
        try
        {
            var match = pattern.Match(input);
            return match.Success ? match.Value : null;
        }
        catch (RegexMatchTimeoutException)
        {
            return null;
        }
    }

    private static string TruncateEvidence(string evidence) =>
        evidence.Length <= RuleConstants.Limits.MaxEvidenceLength
            ? evidence
            : evidence[..(RuleConstants.Limits.MaxEvidenceLength - 3)] + "...";
}
