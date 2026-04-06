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

    private static ScanContext CreateContext(params SkillDefinition[] skills)
    {
        return new ScanContext { Servers = [], Skills = skills };
    }
}
