using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Shouldly;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Osv;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

public class SkillOsvRulesTests
{
    private static readonly SkillDefinition[] Skills = [TestSkills.MakeSkill("demo-skill", "text")];

    private static ScanContext Context(DependencySurface? surface) =>
        new() { Servers = [], Skills = Skills, DependencySurface = surface };

    private static DependencySurface Surface(DependencyQueryStatus status, int deps = 1) =>
        new()
        {
            Dependencies = Enumerable.Range(0, deps).Select(i => new SkillDependency
            {
                Name = $"pkg-{i}", Version = "1.0.0", Ecosystem = "npm",
                Source = "instructions", SkillName = "demo-skill"
            }).ToList(),
            Status = status
        };

    [Fact]
    public async Task OsvRule_SucceededWithVulns_EmitsOneFindingPerVuln()
    {
        var surface = Surface(DependencyQueryStatus.Succeeded) with
        {
            Vulnerabilities =
            [
                new OsvVulnerability
                {
                    Id = "GHSA-aaaa", Summary = "bad", Severity = Severity.High,
                    Ecosystem = "npm", PackageName = "pkg-0", PackageVersion = "1.0.0",
                    SkillName = "demo-skill", Source = "instructions"
                },
                new OsvVulnerability
                {
                    Id = "CVE-2026-1", Summary = "", Severity = Severity.Medium,
                    Ecosystem = "npm", PackageName = "pkg-0", PackageVersion = "1.0.0",
                    SkillName = "demo-skill", Source = "instructions"
                }
            ]
        };

        var findings = (await new SkillOsvVulnerabilityRule().EvaluateAsync(Context(surface))).ToList();

        findings.Count.ShouldBe(2);
        findings[0].RuleId.ShouldBe(RuleConstants.Rules.SkillOsvVulnerability);
        findings[0].Severity.ShouldBe(Severity.High);
        findings[0].Title.ShouldContain("GHSA-aaaa");
        findings[0].Title.ShouldContain("pkg-0");
        findings[0].ServerName.ShouldBe("demo-skill");
        findings[0].Confidence.ShouldBe(0.9);
        findings[0].Source.ShouldBe(FindingSource.Skill);
        findings[1].Title.ShouldContain("CVE-2026-1");
    }

    [Fact]
    public async Task OsvRule_NoSurfaceOrNotSucceeded_EmitsNothing()
    {
        var rule = new SkillOsvVulnerabilityRule();

        (await rule.EvaluateAsync(Context(null))).ShouldBeEmpty();
        (await rule.EvaluateAsync(Context(Surface(DependencyQueryStatus.NotRequested)))).ShouldBeEmpty();
        (await rule.EvaluateAsync(Context(Surface(DependencyQueryStatus.Succeeded)))).ShouldBeEmpty();
    }

    [Fact]
    public async Task SurfaceRule_UncheckedStatuses_EmitOneInfoFinding()
    {
        var rule = new SkillDependencySurfaceRule();

        foreach (var status in new[]
        {
            DependencyQueryStatus.NotRequested,
            DependencyQueryStatus.Offline,
            DependencyQueryStatus.Failed
        })
        {
            var findings = (await rule.EvaluateAsync(Context(Surface(status)))).ToList();

            findings.Count.ShouldBe(1, status.ToString());
            findings[0].RuleId.ShouldBe(RuleConstants.Rules.SkillDependencySurface);
            findings[0].Severity.ShouldBe(Severity.Info);
            findings[0].Description.ShouldContain("pkg-0");
            findings[0].Confidence.ShouldBe(1.0);
        }
    }

    [Fact]
    public async Task SurfaceRule_Failed_IncludesReason()
    {
        var surface = Surface(DependencyQueryStatus.Failed) with { FailureReason = "HttpRequestException" };

        var findings = (await new SkillDependencySurfaceRule().EvaluateAsync(Context(surface))).ToList();

        findings[0].Description.ShouldContain("HttpRequestException");
    }

    [Fact]
    public async Task SurfaceRule_SucceededOrNoDeps_Silent()
    {
        var rule = new SkillDependencySurfaceRule();

        (await rule.EvaluateAsync(Context(Surface(DependencyQueryStatus.Succeeded)))).ShouldBeEmpty();
        (await rule.EvaluateAsync(Context(Surface(DependencyQueryStatus.NotRequested, deps: 0)))).ShouldBeEmpty();
        (await rule.EvaluateAsync(Context(null))).ShouldBeEmpty();
    }

    [Fact]
    public async Task SurfaceRule_ManyPackages_DescriptionCapped()
    {
        var findings = (await new SkillDependencySurfaceRule()
            .EvaluateAsync(Context(Surface(DependencyQueryStatus.Offline, deps: 40)))).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Description.ShouldContain("pkg-24");
        findings[0].Description.ShouldNotContain("pkg-25");
        findings[0].Description.ShouldContain("...");
    }
}
