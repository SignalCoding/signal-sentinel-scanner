// -----------------------------------------------------------------------
// <copyright file="SkillDescriptionOverlapRuleTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

/// <summary>
/// v3.0.0 WP4: SS-037 Cross-Skill Description Overlap.
/// </summary>
public class SkillDescriptionOverlapRuleTests
{
    private const string GitDescription =
        "Create, review and merge pull requests on GitHub repositories. Handles branch creation, commit messages and rebase conflicts.";

    private readonly SkillDescriptionOverlapRule _rule = new();

    [Fact]
    public void Metadata_IsCorrect()
    {
        _rule.Id.ShouldBe("SS-037");
        _rule.OwaspCode.ShouldBe("ASI01");
        _rule.AstCodes.ShouldBe(["AST04"]);
        _rule.EnabledByDefault.ShouldBeTrue();
    }

    [Fact]
    public async Task IdenticalDescriptions_DifferentNames_Medium()
    {
        var ctx = Context(
            Skill("github-pr", GitDescription),
            Skill("gh-helper", GitDescription));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        var f = findings[0];
        f.RuleId.ShouldBe("SS-037");
        f.Severity.ShouldBe(Severity.Medium);
        f.Source.ShouldBe(FindingSource.Skill);
        f.Title.ShouldContain("github-pr");
        f.Title.ShouldContain("gh-helper");
        f.Evidence.ShouldNotBeNull();
        f.Evidence.ShouldContain("jaccard=1.00");
        f.Confidence.ShouldBe(0.9);
        f.ServerName.ShouldBe("github-pr");
        f.SkillFilePath.ShouldBe("/skills/github-pr/SKILL.md");
        f.Description.ShouldContain("/skills/github-pr/SKILL.md");
        f.Description.ShouldContain("/skills/gh-helper/SKILL.md");
    }

    [Fact]
    public async Task TemplatedBoilerplate_DifferentSubjects_NoFinding()
    {
        var ctx = Context(
            Skill("docx", "Use this skill whenever the user asks to create, edit or convert Word documents (docx). Trigger proactively when the user mentions a report, letter or proposal and wants a formatted document."),
            Skill("pdf", "Use this skill whenever the user asks to create, edit or convert PDF documents (pdf). Trigger proactively when the user mentions a report, letter or proposal and wants a formatted document."));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task NearDuplicate_SmallEdit_Fires()
    {
        var ctx = Context(
            Skill("github-pr", GitDescription),
            Skill("gh-helper", GitDescription.Replace("rebase conflicts", "rebase conflicts quickly", StringComparison.Ordinal)));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Confidence.ShouldBe(0.75);
    }

    [Fact]
    public async Task SameCanonicalName_TwoCopies_Skipped()
    {
        // Personal + project copies of the same skill is SS-010 territory, not hijacking.
        var ctx = Context(
            Skill("github-pr", GitDescription, "/home/u/.claude/skills/github-pr/SKILL.md"),
            Skill("github-pr", GitDescription, "/repo/.claude/skills/github-pr/SKILL.md"));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task DifferentDescriptions_NoFinding()
    {
        var ctx = Context(
            Skill("github-pr", GitDescription),
            Skill("csv-tools", "Parse, filter and aggregate CSV spreadsheets. Supports quoted fields, custom delimiters and streaming large files."));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task PartialOverlap_BelowThreshold_NoFinding()
    {
        var ctx = Context(
            Skill("github-pr", GitDescription),
            Skill("gitlab-mr", "Create, review and merge merge-requests on GitLab projects. Handles pipelines, approvals, milestones and issue boards."));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task ShortDescriptions_Skipped()
    {
        // Under MinTokens meaningful words: "Runs tests" style one-liners collide by chance.
        var ctx = Context(
            Skill("a", "Runs the unit tests."),
            Skill("b", "Runs the unit tests."));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task MissingDescription_Skipped()
    {
        var ctx = Context(
            Skill("a", null),
            Skill("b", null));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task ThreeWayDuplicate_ReportsEachPair()
    {
        var ctx = Context(
            Skill("a", GitDescription),
            Skill("b", GitDescription),
            Skill("c", GitDescription));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(3);
    }

    [Fact]
    public async Task NoSkills_NoFindings()
    {
        var findings = await _rule.EvaluateAsync(new ScanContext { Servers = [], Skills = [] });

        findings.ShouldBeEmpty();
    }

    [Fact]
    public void Tokenise_LowercasesDropsStopWordsAndShortTokens()
    {
        var tokens = SkillDescriptionOverlapRule.Tokenise("The Agent can USE this to Merge PRs, or to re-base a branch!");

        tokens.ShouldBe(["merge", "prs", "base", "branch"], ignoreOrder: true);
    }

    [Fact]
    public void Jaccard_ComputesSetSimilarity()
    {
        var a = new HashSet<string>(StringComparer.Ordinal) { "one", "two", "three", "four" };
        var b = new HashSet<string>(StringComparer.Ordinal) { "three", "four", "five", "six" };

        SkillDescriptionOverlapRule.Jaccard(a, b).ShouldBe(2.0 / 6.0, 0.0001);
        SkillDescriptionOverlapRule.Jaccard(a, a).ShouldBe(1.0);
        SkillDescriptionOverlapRule.Jaccard([], []).ShouldBe(0.0);
    }

    // ---------------------------------------------------------------- helpers

    private static ScanContext Context(params SkillDefinition[] skills) =>
        new() { Servers = [], Skills = skills };

    private static SkillDefinition Skill(string name, string? description, string? path = null) =>
        new()
        {
            Name = name,
            Description = description,
            InstructionsBody = "Body.",
            RawContent = "Body.",
            FilePath = path ?? $"/skills/{name}/SKILL.md",
            SourcePlatform = "claude"
        };
}
