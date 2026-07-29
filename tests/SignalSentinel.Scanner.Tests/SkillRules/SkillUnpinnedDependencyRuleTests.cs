// -----------------------------------------------------------------------
// <copyright file="SkillUnpinnedDependencyRuleTests.cs" company="Signal Coding Limited">
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

public class SkillUnpinnedDependencyRuleTests
{
    private readonly SkillUnpinnedDependencyRule _rule = new();

    [Theory]
    [InlineData("Download the helper from https://github.com/acme/tool/blob/main/setup.py and run it.")]
    [InlineData("Fetch https://github.com/acme/tool/raw/master/payload.sh before continuing.")]
    [InlineData("See https://github.com/acme/tool/tree/develop for the latest scripts.")]
    public async Task Evaluate_FloatingGitHubBranchReference_Fires(string body)
    {
        var skill = new SkillDefinition
        {
            Name = "dep-skill",
            InstructionsBody = body,
            RawContent = body,
            FilePath = "/skills/dep-skill/SKILL.md"
        };
        var context = new ScanContext { Servers = [], Skills = [skill] };

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.ShouldContain(f =>
            f.RuleId == "SS-029" &&
            f.Severity == Severity.Medium &&
            f.Source == FindingSource.Skill);
    }

    [Fact]
    public async Task Evaluate_UnpinnedGitInstallUrl_Fires()
    {
        var body = "Install the dependency with: pip install git+https://github.com/acme/tool.git";
        var skill = new SkillDefinition
        {
            Name = "pip-skill",
            InstructionsBody = body,
            RawContent = body,
            FilePath = "/skills/pip-skill/SKILL.md"
        };
        var context = new ScanContext { Servers = [], Skills = [skill] };

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.ShouldContain(f => f.RuleId == "SS-029");
    }

    [Fact]
    public async Task Evaluate_PinnedGitInstallUrl_DoesNotFire()
    {
        var body = "Install the dependency with: pip install git+https://github.com/acme/tool.git@v2.1.0";
        var skill = new SkillDefinition
        {
            Name = "pinned-pip-skill",
            InstructionsBody = body,
            RawContent = body,
            FilePath = "/skills/pinned-pip-skill/SKILL.md"
        };
        var context = new ScanContext { Servers = [], Skills = [skill] };

        var findings = await _rule.EvaluateAsync(context);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_PinnedTagOrShaReference_DoesNotFire()
    {
        var body = "See https://github.com/acme/tool/blob/v2.1.0/setup.py and " +
            "https://github.com/acme/tool/blob/a1b2c3d4e5f6/setup.py for reference.";
        var skill = new SkillDefinition
        {
            Name = "pinned-skill",
            InstructionsBody = body,
            RawContent = body,
            FilePath = "/skills/pinned-skill/SKILL.md"
        };
        var context = new ScanContext { Servers = [], Skills = [skill] };

        var findings = await _rule.EvaluateAsync(context);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_ScriptWithUnpinnedReference_Fires()
    {
        var skill = new SkillDefinition
        {
            Name = "script-dep-skill",
            InstructionsBody = "Runs a helper script.",
            RawContent = "irrelevant",
            FilePath = "/skills/script-dep-skill/SKILL.md",
            Scripts =
            [
                new BundledScript
                {
                    RelativePath = "install.sh",
                    FullPath = "/skills/script-dep-skill/install.sh",
                    Language = ScriptLanguage.Bash,
                    Content = "pip install git+https://github.com/acme/tool.git\n",
                    FileSize = 48
                }
            ]
        };
        var context = new ScanContext { Servers = [], Skills = [skill] };

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.ShouldContain(f => f.RuleId == "SS-029" && f.Evidence != null);
    }

    [Fact]
    public async Task Evaluate_NoGitHubReference_DoesNotFire()
    {
        var body = "Reads a config file and formats a table.";
        var skill = new SkillDefinition
        {
            Name = "clean-skill",
            InstructionsBody = body,
            RawContent = body,
            FilePath = "/skills/clean-skill/SKILL.md"
        };
        var context = new ScanContext { Servers = [], Skills = [skill] };

        var findings = await _rule.EvaluateAsync(context);

        findings.ShouldBeEmpty();
    }
}
