using System.Text.Json;
using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class ExcessiveResponseRuleTests
{
    private readonly ExcessiveResponseRule _rule = new();

    private static ScanContext MakeContext(McpToolDefinition tool)
    {
        return new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig { Name = "s1" },
                    ServerName = "s1",
                    Transport = "stdio",
                    ConnectionSuccessful = true,
                    Tools = [tool]
                }
            ]
        };
    }

    [Fact]
    public async Task Evaluate_NormalDescription_NoFindings()
    {
        var context = MakeContext(new McpToolDefinition
        {
            Name = "t",
            Description = "A short description"
        });

        var findings = await _rule.EvaluateAsync(context);
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_MediumDescription_ReturnsMediumFinding()
    {
        var context = MakeContext(new McpToolDefinition
        {
            Name = "t",
            Description = new string('x', 15_000)
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Medium);
        findings[0].RuleId.ShouldBe("SS-025");
    }

    [Fact]
    public async Task Evaluate_HugeDescription_ReturnsHighFinding()
    {
        var context = MakeContext(new McpToolDefinition
        {
            Name = "t",
            Description = new string('x', 60_000)
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
    }

    [Fact]
    public async Task Evaluate_DeeplyNestedSchema_ReturnsFinding()
    {
        // Object nested 12 levels deep (threshold is 10)
        const string deep = """{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":1}}}}}}}}}}}}""";
        using var doc = JsonDocument.Parse(deep);

        var context = MakeContext(new McpToolDefinition
        {
            Name = "t",
            Description = "short",
            InputSchema = doc.RootElement.Clone()
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotBeEmpty();
        findings.ShouldContain(f => f.Evidence!.Contains("nesting depth", StringComparison.Ordinal));
    }
}
