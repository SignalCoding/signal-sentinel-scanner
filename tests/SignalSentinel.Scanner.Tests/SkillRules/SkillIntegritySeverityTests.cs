// -----------------------------------------------------------------------
// <copyright file="SkillIntegritySeverityTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

/// <summary>
/// v3.0.2 (N2): the unsigned-skill finding emitted by <see cref="SkillIntegrityRule"/>
/// (SS-024) moves from <see cref="Severity.Medium"/> to <see cref="Severity.Info"/>.
/// Title, description and remediation are unchanged. Extends the existing SS-024
/// coverage in <c>SkillIntegrityRuleTests</c> rather than editing its assertions.
/// Spec: _docs/ai/specs/v3.0.2-skill-noise.md N2.
/// </summary>
public class SkillIntegritySeverityTests
{
    private readonly SkillIntegrityRule _rule = new();

    [Fact]
    public async Task N2_Evaluate_SkillWithoutSignature_ReturnsInfoSeverity()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"skill-integrity-severity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var skillPath = Path.Combine(tempDir, "SKILL.md");
            File.WriteAllText(skillPath, "# Test skill");

            var skill = new SkillDefinition
            {
                Name = "test",
                InstructionsBody = string.Empty,
                RawContent = "# Test skill",
                FilePath = skillPath
            };

            var context = new ScanContext { Servers = [], Skills = [skill] };
            var findings = (await _rule.EvaluateAsync(context)).ToList();

            findings.Count.ShouldBe(1);
            findings[0].RuleId.ShouldBe(RuleConstants.Rules.SkillIntegrityVerification);
            findings[0].Severity.ShouldBe(Severity.Info);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task N2_Evaluate_SkillWithoutSignature_TitleAndRemediationUnchanged()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"skill-integrity-severity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var skillPath = Path.Combine(tempDir, "SKILL.md");
            File.WriteAllText(skillPath, "# Test skill");

            var skill = new SkillDefinition
            {
                Name = "test",
                InstructionsBody = string.Empty,
                RawContent = "# Test skill",
                FilePath = skillPath
            };

            var context = new ScanContext { Servers = [], Skills = [skill] };
            var findings = (await _rule.EvaluateAsync(context)).ToList();

            findings.Count.ShouldBe(1);
            findings[0].Title.ShouldBe("Skill Not Signed: test");
            findings[0].Remediation.ShouldContain("cosign/sigstore");
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }
}
