using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

public class SkillIntegrityRuleTests
{
    private readonly SkillIntegrityRule _rule = new();

    [Fact]
    public async Task Evaluate_SkillWithoutSignature_ReturnsMediumFinding()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"skill-integrity-{Guid.NewGuid():N}");
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
            findings[0].RuleId.ShouldBe("SS-024");
            findings[0].Severity.ShouldBe(Severity.Medium);
            findings[0].Source.ShouldBe(FindingSource.Skill);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Evaluate_SkillWithSignature_ReturnsNoFindings()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"skill-integrity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var skillPath = Path.Combine(tempDir, "SKILL.md");
            File.WriteAllText(skillPath, "# Test skill");
            File.WriteAllText(Path.Combine(tempDir, "SHA256SUMS"), "abcdef  SKILL.md");

            var skill = new SkillDefinition
            {
                Name = "test",
                InstructionsBody = string.Empty,
                RawContent = "# Test skill",
                FilePath = skillPath
            };

            var context = new ScanContext { Servers = [], Skills = [skill] };
            var findings = await _rule.EvaluateAsync(context);

            findings.ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Evaluate_NoSkills_ReturnsEmpty()
    {
        var findings = await _rule.EvaluateAsync(new ScanContext { Servers = [], Skills = [] });
        findings.ShouldBeEmpty();
    }
}
