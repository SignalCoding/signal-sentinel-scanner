// -----------------------------------------------------------------------
// <copyright file="SkillIntegrationTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using FluentAssertions;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

public class SkillIntegrationTests
{
    private static string GetTestDataPath(string subDir)
    {
        // Navigate from bin/Release/net10.0 up to the test project, then into TestData
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var projectDir = Path.GetFullPath(Path.Combine(baseDir, "..", "..", ".."));
        return Path.Combine(projectDir, "TestData", subDir);
    }

    [Fact]
    public async Task MaliciousSkill_ParsesCorrectly()
    {
        var skillPath = Path.Combine(GetTestDataPath("malicious-skill"), "SKILL.md");
        var skill = await SkillReader.ReadAsync(skillPath);

        skill.Should().NotBeNull();
        skill!.Name.Should().Be("code-formatter");
        skill.Description.Should().Be("Format code according to project conventions");
        skill.Context.Should().Be("full");
        skill.Agent.Should().Be("custom-unrestricted");
        skill.Scripts.Should().NotBeEmpty();
        skill.Scripts.Should().Contain(s => s.RelativePath == "helper.py");
    }

    [Fact]
    public async Task MaliciousSkill_AllRulesFire()
    {
        var skillPath = Path.Combine(GetTestDataPath("malicious-skill"), "SKILL.md");
        var skill = await SkillReader.ReadAsync(skillPath);
        skill.Should().NotBeNull();

        var context = new ScanContext
        {
            Servers = [],
            Skills = [skill!]
        };

        var allRules = new IRule[]
        {
            new SkillInjectionRule(),
            new SkillScopeViolationRule(),
            new SkillCredentialAccessRule(),
            new SkillExfiltrationRule(),
            new SkillObfuscationRule(),
            new SkillScriptPayloadRule(),
            new SkillExcessivePermRule(),
            new SkillHiddenContentRule()
        };

        var allFindings = new List<Finding>();
        foreach (var rule in allRules)
        {
            var findings = await rule.EvaluateAsync(context);
            allFindings.AddRange(findings);
        }

        // Should find many issues
        allFindings.Should().NotBeEmpty();
        allFindings.Count.Should().BeGreaterThanOrEqualTo(5);

        // All findings should be skill-sourced
        allFindings.Should().AllSatisfy(f => f.Source.Should().Be(FindingSource.Skill));

        // Should have critical findings (SSH key access, RCE, etc.)
        allFindings.Should().Contain(f => f.Severity == Severity.Critical);

        // Should have high findings
        allFindings.Should().Contain(f => f.Severity == Severity.High);
    }

    [Fact]
    public async Task CleanSkill_NoFindings()
    {
        var skillPath = Path.Combine(GetTestDataPath("clean-skill"), "SKILL.md");
        var skill = await SkillReader.ReadAsync(skillPath);
        skill.Should().NotBeNull();

        var context = new ScanContext
        {
            Servers = [],
            Skills = [skill!]
        };

        var allRules = new IRule[]
        {
            new SkillInjectionRule(),
            new SkillScopeViolationRule(),
            new SkillCredentialAccessRule(),
            new SkillExfiltrationRule(),
            new SkillObfuscationRule(),
            new SkillScriptPayloadRule(),
            new SkillExcessivePermRule(),
            new SkillHiddenContentRule()
        };

        var allFindings = new List<Finding>();
        foreach (var rule in allRules)
        {
            var findings = await rule.EvaluateAsync(context);
            allFindings.AddRange(findings);
        }

        allFindings.Should().BeEmpty();
    }

    [Fact]
    public async Task SkillReader_ReadDirectory_FindsSkills()
    {
        var testDataDir = GetTestDataPath("");
        var skills = await SkillReader.ReadDirectoryAsync(testDataDir);

        skills.Should().HaveCount(2);
        skills.Should().Contain(s => s.Name == "code-formatter");
        skills.Should().Contain(s => s.Name == "greeting-helper");
    }
}
