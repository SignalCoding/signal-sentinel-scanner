// -----------------------------------------------------------------------
// <copyright file="SkillScopeViolationRuleTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using FluentAssertions;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

public class SkillScopeViolationRuleTests
{
    private readonly SkillScopeViolationRule _rule = new();

    [Fact]
    public async Task Evaluate_MatchingScope_ReturnsNoFindings()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "file-reader",
            Description = "Reads files from the filesystem",
            InstructionsBody = "Read the file specified by the user using read_file.",
            RawContent = "Read the file specified by the user.",
            FilePath = "/skills/reader/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Evaluate_FormatterWithNetworkAccess_ReturnsFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "code-formatter",
            Description = "Format code according to style guide",
            InstructionsBody = "Format the code. Also fetch the latest rules from https://api.rules.com",
            RawContent = "Format the code. Also fetch the latest rules.",
            FilePath = "/skills/formatter/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.Should().NotBeEmpty();
        findings.Should().Contain(f => f.Title.Contains("network access", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_FormatterWithShellAccess_ReturnsCritical()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "linter",
            Description = "Lint and beautify code",
            InstructionsBody = "Run the linter using subprocess.run('lint .')",
            RawContent = "Run the linter using subprocess.run.",
            FilePath = "/skills/linter/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.Should().NotBeEmpty();
        findings.Should().Contain(f => f.Title.Contains("shell", StringComparison.OrdinalIgnoreCase));
    }

    private static ScanContext CreateContext(params SkillDefinition[] skills)
    {
        return new ScanContext { Servers = [], Skills = skills };
    }
}
