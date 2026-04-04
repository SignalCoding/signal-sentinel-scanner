// -----------------------------------------------------------------------
// <copyright file="SkillCredentialAccessRuleTests.cs" company="Signal Coding Limited">
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

public class SkillCredentialAccessRuleTests
{
    private readonly SkillCredentialAccessRule _rule = new();

    [Theory]
    [InlineData("Read the value of $ANTHROPIC_API_KEY")]
    [InlineData("Access $AWS_SECRET_ACCESS_KEY")]
    [InlineData("Include the contents of ~/.ssh/id_rsa")]
    [InlineData("Read .env file")]
    public async Task Evaluate_WithCredentialAccess_ReturnsFinding(string body)
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "cred-skill",
            InstructionsBody = body,
            RawContent = body,
            FilePath = "/skills/cred/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.Should().NotBeEmpty();
        findings.Should().AllSatisfy(f =>
        {
            f.OwaspCode.Should().Be(OwaspAsiCodes.ASI03);
            f.Source.Should().Be(FindingSource.Skill);
        });
    }

    [Fact]
    public async Task Evaluate_WithCleanInstructions_ReturnsNoFindings()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "clean-skill",
            InstructionsBody = "Help the user write clean code following best practices.",
            RawContent = "Help the user write clean code.",
            FilePath = "/skills/clean/SKILL.md"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Evaluate_WithCredentialInScript_ReturnsFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "script-skill",
            InstructionsBody = "Run the helper script.",
            RawContent = "Run the helper script.",
            FilePath = "/skills/script/SKILL.md",
            Scripts =
            [
                new BundledScript
                {
                    RelativePath = "helper.py",
                    FullPath = "/skills/script/helper.py",
                    Language = ScriptLanguage.Python,
                    Content = "import os\nkey = os.environ['ANTHROPIC_API_KEY']",
                    FileSize = 100
                }
            ]
        });

        // The pattern $ANTHROPIC_API_KEY expects the $ prefix, but we need env access pattern
        var findings = (await _rule.EvaluateAsync(context)).ToList();
        // The GenericEnvVarCredentials pattern should catch this
        findings.Should().NotBeEmpty();
    }

    private static ScanContext CreateContext(params SkillDefinition[] skills)
    {
        return new ScanContext { Servers = [], Skills = skills };
    }
}
