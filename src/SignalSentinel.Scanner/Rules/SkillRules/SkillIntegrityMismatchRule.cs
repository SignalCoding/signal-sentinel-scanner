// -----------------------------------------------------------------------
// <copyright file="SkillIntegrityMismatchRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.SkillParser;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-034: A skill ships a checksum manifest and at least one entry does not verify.
/// Maps to OWASP ASI04 (Supply Chain Vulnerabilities).
/// </summary>
/// <remarks>
/// SS-024 asks "is there an integrity artefact at all?". This rule asks the sharper
/// question "does the artefact that is present actually hold?". A mismatch is High:
/// either the publisher shipped a stale manifest or the content changed after it was
/// signed, and the scanner cannot tell which. A listed-but-missing file is Medium; an
/// entry that cannot be checked (path escapes the package, unreadable) is Low.
/// </remarks>
public sealed class SkillIntegrityMismatchRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.SkillIntegrityMismatch;

    /// <inheritdoc />
    public string Name => "Skill Integrity Mismatch";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI04;

    /// <inheritdoc />
    public string Description =>
        "Verifies every entry in a skill's SHA256SUMS manifest against the files on disk and flags mismatches, missing files, and unverifiable entries.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST02, OwaspAstCodes.AST07];

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var report = IntegrityVerifier.Verify(skill);
            if (report.ChecksumResults.Count == 0)
            {
                continue;
            }

            var mismatches = report.ChecksumResults.Where(r => r.Status == ChecksumStatus.Mismatch).ToList();
            var missing = report.ChecksumResults.Where(r => r.Status == ChecksumStatus.Missing).ToList();
            var invalid = report.ChecksumResults.Where(r => r.Status == ChecksumStatus.Invalid).ToList();

            if (mismatches.Count > 0)
            {
                findings.Add(Create(skill, Severity.High,
                    $"Skill Checksum Mismatch: {skill.Name}",
                    $"{mismatches.Count} file(s) in skill '{skill.Name}' do not match the hashes in its checksum manifest. " +
                    "Either the manifest is stale or the files were modified after publication. Treat the skill as tampered until the publisher confirms.",
                    "Re-download the skill from its canonical source and compare. If the publisher's copy also mismatches, report it upstream. Do not run the skill.",
                    string.Join(", ", mismatches.Select(m => m.RelativePath)),
                    0.95));
            }

            if (missing.Count > 0)
            {
                findings.Add(Create(skill, Severity.Medium,
                    $"Skill Manifest Lists Missing File: {skill.Name}",
                    $"{missing.Count} file(s) listed in the checksum manifest of skill '{skill.Name}' are not present. " +
                    "The package is incomplete or the manifest describes a different release.",
                    "Obtain the complete package or a manifest that matches this release.",
                    string.Join(", ", missing.Select(m => m.RelativePath)),
                    0.9));
            }

            if (invalid.Count > 0)
            {
                findings.Add(Create(skill, Severity.Low,
                    $"Skill Manifest Entry Unverifiable: {skill.Name}",
                    $"{invalid.Count} manifest entry(ies) in skill '{skill.Name}' could not be verified: the path escapes the skill directory, the file is unreadable, or it exceeds the hashing size limit.",
                    "Manifest paths must be relative and stay within the skill directory. Remove or correct the offending entries.",
                    string.Join(", ", invalid.Select(m => m.RelativePath)),
                    0.8));
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private Finding Create(SkillDefinition skill, Severity severity, string title, string description, string remediation, string evidence, double confidence)
    {
        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = severity,
            Title = title,
            Description = description,
            Remediation = remediation,
            ServerName = skill.Name,
            Evidence = DescriptionScan.Truncate(evidence),
            Confidence = confidence,
            Source = FindingSource.Skill,
            SkillFilePath = skill.FilePath
        };
    }
}
