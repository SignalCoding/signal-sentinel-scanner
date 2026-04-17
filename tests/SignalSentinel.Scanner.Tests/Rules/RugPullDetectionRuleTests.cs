using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class RugPullDetectionRuleTests
{
    [Fact]
    public async Task Evaluate_NoComparison_ReturnsNoFindings()
    {
        var rule = new RugPullDetectionRule(null);
        var findings = await rule.EvaluateAsync(new ScanContext { Servers = [] });
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_BaselineNotLoaded_ReturnsNoFindings()
    {
        var rule = new RugPullDetectionRule(new BaselineComparison { BaselineLoaded = false });
        var findings = await rule.EvaluateAsync(new ScanContext { Servers = [] });
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_Mutation_ReturnsCriticalFinding()
    {
        var comparison = new BaselineComparison
        {
            BaselineLoaded = true,
            MutatedTools =
            [
                new SchemaMutation
                {
                    Tool = new ToolIdentity { ServerName = "s1", ToolName = "read" },
                    Type = MutationType.DescriptionChanged,
                    BaselineHash = "sha256:a",
                    CurrentHash = "sha256:b",
                    Summary = "desc changed"
                }
            ]
        };
        var rule = new RugPullDetectionRule(comparison);

        var findings = (await rule.EvaluateAsync(new ScanContext { Servers = [] })).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Critical);
        findings[0].RuleId.ShouldBe("SS-022");
    }

    [Fact]
    public async Task Evaluate_Addition_ReturnsHighFinding()
    {
        var comparison = new BaselineComparison
        {
            BaselineLoaded = true,
            AddedTools = [new ToolIdentity { ServerName = "s1", ToolName = "new_tool" }]
        };
        var rule = new RugPullDetectionRule(comparison);

        var findings = (await rule.EvaluateAsync(new ScanContext { Servers = [] })).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
        findings[0].Title.ShouldContain("new_tool");
    }

    [Fact]
    public async Task Evaluate_Removal_ReturnsMediumFinding()
    {
        var comparison = new BaselineComparison
        {
            BaselineLoaded = true,
            RemovedTools = [new ToolIdentity { ServerName = "s1", ToolName = "gone_tool" }]
        };
        var rule = new RugPullDetectionRule(comparison);

        var findings = (await rule.EvaluateAsync(new ScanContext { Servers = [] })).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Medium);
    }
}
