// -----------------------------------------------------------------------
// <copyright file="SkillUnpinnedDependencyRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-029 (v2.5.0, G14): flags skills that reference a GitHub-hosted dependency by
/// a floating branch (<c>main</c>/<c>master</c>/...) or an unpinned
/// <c>git+https://</c> install URL, rather than a pinned tag/release or commit SHA.
/// This is the documented "SkillJacking" supply-chain vector (Air Security, July
/// 2026): 925 published skills were found resting on take-able dependencies
/// (deleted GitHub accounts, expired domains), reaching an estimated 134K agents -
/// including a skills.sh skill with 11,483 installs hijacked after its upstream
/// account was deleted and re-registered by an attacker. A floating reference
/// trusts whoever currently controls the account/branch, not a fixed, auditable
/// artefact. Maps to OWASP AST02 (Supply Chain) / AST07 (Update Drift).
/// </summary>
public sealed partial class SkillUnpinnedDependencyRule : IRule
{
    public string Id => RuleConstants.Rules.SkillUnpinnedDependency;
    public string Name => "Skill Unpinned Dependency Reference (SkillJacking)";
    public string OwaspCode => OwaspAsiCodes.ASI04;
    public string Description =>
        "Detects skill instructions or bundled scripts that reference a GitHub " +
        "dependency by a floating branch or unpinned git+https install URL " +
        "instead of a pinned tag, release, or commit SHA - the account/repo " +
        "hijacking vector documented as 'SkillJacking'.";
    public bool EnabledByDefault => true;
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST02, OwaspAstCodes.AST07];

    // A github.com blob/raw/tree URL pointing at a floating branch name rather than
    // a version tag or commit SHA. Branch names here are the common defaults; a tag
    // like "v2.1.0" or a 7-40 char hex SHA will not match this list.
    [GeneratedRegex(
        @"https?://(?:www\.)?github\.com/[\w.-]+/[\w.-]+/(?:blob|raw|tree)/(?:main|master|head|develop|dev|latest|trunk)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex UnpinnedGitHubRef();

    // pip/npm-style "git+https://github.com/user/repo(.git)" install reference with
    // no "@<ref>" pin suffix. The trailing segments are wrapped in atomic groups
    // (?>...) so the engine can't shrink an already-greedy match just to dodge the
    // "not followed by @" lookahead - without that, a pinned URL like
    // ".../repo.git@v1.0.0" would still (incorrectly) match on a truncated prefix.
    [GeneratedRegex(
        @"git\+https?://github\.com/(?>[\w.-]+)/(?>[\w.-]+)(?>\.git)?(?!@)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex UnpinnedGitInstall();

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var evidence = SafeMatch(UnpinnedGitHubRef(), skill.InstructionsBody)
                ?? SafeMatch(UnpinnedGitInstall(), skill.InstructionsBody);
            var evidenceSource = "instructions";

            if (evidence is null)
            {
                foreach (var script in skill.Scripts)
                {
                    var scriptMatch = SafeMatch(UnpinnedGitHubRef(), script.Content)
                        ?? SafeMatch(UnpinnedGitInstall(), script.Content);
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

            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                AstCodes = AstCodes,
                Severity = Severity.Medium,
                Title = $"Skill References Unpinned Dependency: {skill.Name}",
                Description =
                    $"Skill '{skill.Name}' ({evidenceSource}) references a GitHub " +
                    "dependency by a floating branch or an unpinned git+https install " +
                    "URL, rather than a fixed tag, release, or commit SHA. If the " +
                    "referenced account or repository is later deleted and " +
                    "re-registered by someone else, or the branch's contents change, " +
                    "the skill will silently pull in attacker-controlled code on its " +
                    "next run - the 'SkillJacking' vector documented against 925 " +
                    "published skills (Air Security, July 2026).",
                Remediation =
                    "Pin the dependency to a specific release tag or commit SHA " +
                    "(e.g. `.../blob/v2.1.0/...` or `git+https://.../repo.git@<sha>`) " +
                    "instead of a floating branch name, and re-verify the pin " +
                    "periodically.",
                ServerName = skill.Name,
                Evidence = TruncateEvidence(evidence),
                Confidence = 0.75,
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
