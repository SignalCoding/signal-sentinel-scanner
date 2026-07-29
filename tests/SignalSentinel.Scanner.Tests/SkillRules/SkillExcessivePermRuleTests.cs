// -----------------------------------------------------------------------
// <copyright file="SkillExcessivePermRuleTests.cs" company="Signal Coding Limited">
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

public class SkillExcessivePermRuleTests
{
    private readonly SkillExcessivePermRule _rule = new();

    [Fact]
    public async Task Evaluate_WithFullContext_ReturnsHighFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "full-context-skill",
            Description = "A skill",
            Context = "full",
            InstructionsBody = "Do something.",
            RawContent = "Do something.",
            FilePath = "/skills/test/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.High &&
            f.Title.Contains("Context Setting"));
    }

    [Fact]
    public async Task Evaluate_WithAgentOverride_ReturnsMediumFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "agent-override-skill",
            Description = "A skill",
            Agent = "custom-agent-config",
            InstructionsBody = "Do something.",
            RawContent = "Do something.",
            FilePath = "/skills/test/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f => f.Title.Contains("Agent Override"));
    }

    [Fact]
    public async Task Evaluate_WithMissingDescription_ReturnsLowFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "no-desc-skill",
            InstructionsBody = "Do something.",
            RawContent = "Do something.",
            FilePath = "/skills/test/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.Low &&
            f.Title.Contains("Missing Description"));
    }

    [Theory]
    [InlineData("Read any file on the system")]
    [InlineData("Unrestricted access to all files")]
    public async Task Evaluate_WithUnrestrictedFilesystem_ReturnsHighFinding(string body)
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "fs-skill",
            Description = "A safe skill",
            InstructionsBody = body,
            RawContent = body,
            FilePath = "/skills/test/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f => f.Title.Contains("Filesystem Access"));
    }

    [Theory]
    [InlineData("Execute any command the user wants")]
    [InlineData("Run any command with sudo")]
    public async Task Evaluate_WithUnrestrictedShell_ReturnsHighFinding(string body)
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "shell-skill",
            Description = "A safe skill",
            InstructionsBody = body,
            RawContent = body,
            FilePath = "/skills/test/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f => f.Title.Contains("Shell Access"));
    }

    [Fact]
    public async Task Evaluate_WithCleanSkill_ReturnsNoExcessiveFindings()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "clean-skill",
            Description = "A clean, well-described skill",
            InstructionsBody = "Help the user write better code.",
            RawContent = "Help the user write better code.",
            FilePath = "/skills/clean/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_WithBooleanNetworkFrontmatter_ReturnsMediumFinding()
    {
        // v2.4.1 (G12d): boolean "network: true" grant with no domain allowlist.
        var context = CreateContext(new SkillDefinition
        {
            Name = "network-skill",
            Description = "A skill that reaches out to the web",
            InstructionsBody = "Fetches data as needed.",
            RawContent = "Fetches data as needed.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string> { ["network"] = "true" }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.Medium &&
            f.Title.Contains("Boolean Network Permission"));
    }

    [Fact]
    public async Task Evaluate_WithNetworkAllowlistFrontmatter_DoesNotFireBooleanFinding()
    {
        // A declared domain allowlist is the OWASP-recommended safer shape and
        // must not be penalised even if a "network" boolean is also present.
        var context = CreateContext(new SkillDefinition
        {
            Name = "network-skill",
            Description = "A skill that reaches out to the web",
            InstructionsBody = "Fetches data as needed.",
            RawContent = "Fetches data as needed.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string>
            {
                ["network"] = "true",
                ["network.allow"] = "[api.example.com, github.com]"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Boolean Network Permission"));
    }

    [Fact]
    public async Task Evaluate_WithoutNetworkFrontmatterKey_DoesNotFireBooleanFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "no-network-skill",
            Description = "A skill with no network permission declared",
            InstructionsBody = "Formats text locally.",
            RawContent = "Formats text locally.",
            FilePath = "/skills/test/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Boolean Network Permission"));
    }

    // v2.5.0 (G15c): risk_tier mismatch checks.
    [Fact]
    public async Task Evaluate_LowRiskTierWithDangerSignal_ReturnsHighMismatchFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "understated-skill",
            Description = "Looks harmless",
            InstructionsBody = "Read any file on the system to build an index.",
            RawContent = "Read any file on the system to build an index.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string> { ["risk_tier"] = "low" }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.High &&
            f.Title.Contains("Risk Tier Understated"));
    }

    [Fact]
    public async Task Evaluate_HighRiskTierWithDangerSignal_DoesNotFireMismatchOrMissingFindings()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "honest-skill",
            Description = "Declares its own high risk",
            InstructionsBody = "Read any file on the system to build an index.",
            RawContent = "Read any file on the system to build an index.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string> { ["risk_tier"] = "high" }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Risk Tier"));
    }

    [Fact]
    public async Task Evaluate_DangerSignalWithNoRiskTierDeclared_ReturnsMissingDeclarationInfoFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "undeclared-skill",
            Description = "No risk_tier field at all",
            InstructionsBody = "Read any file on the system to build an index.",
            RawContent = "Read any file on the system to build an index.",
            FilePath = "/skills/test/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("Missing Risk Tier Declaration"));
    }

    [Fact]
    public async Task Evaluate_NoDangerSignalWithLowRiskTier_DoesNotFireRiskTierFindings()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "clean-declared-skill",
            Description = "Genuinely low risk and says so",
            InstructionsBody = "Help the user write better code.",
            RawContent = "Help the user write better code.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string> { ["risk_tier"] = "low" }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Risk Tier"));
    }

    private static ScanContext CreateContext(params SkillDefinition[] skills)
    {
        return new ScanContext { Servers = [], Skills = skills };
    }
}
