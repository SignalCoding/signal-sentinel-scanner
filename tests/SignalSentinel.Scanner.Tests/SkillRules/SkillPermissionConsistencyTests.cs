// -----------------------------------------------------------------------
// <copyright file="SkillPermissionConsistencyTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Spec: _docs/ai/specs/ss017-scoped-declarations.md, R3. #92's D1 made a
// declared network.allow/files.write scope suppress an SS-012 "undeclared
// capability" finding, while its A1 made the same declaration raise SS-017's
// implied risk floor - the same honest declaration was rewarded by one rule
// and punished by the other. This asserts the two rules now agree.

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

public class SkillPermissionConsistencyTests
{
    private readonly SkillScopeViolationRule _scopeRule = new();
    private readonly SkillExcessivePermRule _permRule = new();

    [Fact]
    public async Task DeclaredNarrowNetworkAllow_SuppressesSs012_AndDoesNotRaiseSs017Floor()
    {
        var skill = new SkillDefinition
        {
            Name = "weather-formatter",
            Description = "Formats weather data for display",
            InstructionsBody = "Fetches data from https://api.weather.example/forecast and formats it.",
            RawContent = "Fetches data from https://api.weather.example/forecast and formats it.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string>
            {
                ["risk_tier"] = "L1",
                ["network.allow"] = "[api.weather.example]"
            }
        };

        var scopeContext = new ScanContext { Servers = [], Skills = [skill] };
        var permContext = new ScanContext { Servers = [], Skills = [skill] };

        var scopeFindings = (await _scopeRule.EvaluateAsync(scopeContext)).ToList();
        var permFindings = (await _permRule.EvaluateAsync(permContext)).ToList();

        scopeFindings.ShouldNotContain(f => f.Title.Contains("Undeclared network access", StringComparison.Ordinal),
            "A declared network.allow scope is an explicit declaration; SS-012 must not call it undeclared.");
        permFindings.ShouldNotContain(f => f.Title.Contains("Risk Tier", StringComparison.Ordinal),
            "The same narrow, honest declaration must not raise SS-017's implied risk floor either.");
    }

    [Fact]
    public async Task DeclaredNarrowFilesWrite_SuppressesSs012_AndDoesNotRaiseSs017Floor()
    {
        var skill = new SkillDefinition
        {
            Name = "report-saver",
            Description = "Saves a formatted report",
            InstructionsBody = "Writes the report to reports/summary.md when done.",
            RawContent = "Writes the report to reports/summary.md when done.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string>
            {
                ["risk_tier"] = "L1",
                ["files.write"] = "[reports/summary.md]"
            }
        };

        var scopeContext = new ScanContext { Servers = [], Skills = [skill] };
        var permContext = new ScanContext { Servers = [], Skills = [skill] };

        var scopeFindings = (await _scopeRule.EvaluateAsync(scopeContext)).ToList();
        var permFindings = (await _permRule.EvaluateAsync(permContext)).ToList();

        scopeFindings.ShouldNotContain(f => f.Title.Contains("Undeclared filesystem access", StringComparison.Ordinal),
            "A declared files.write scope is an explicit declaration; SS-012 must not call it undeclared.");
        permFindings.ShouldNotContain(f => f.Title.Contains("Risk Tier", StringComparison.Ordinal),
            "The same narrow, honest declaration must not raise SS-017's implied risk floor either.");
    }
}
