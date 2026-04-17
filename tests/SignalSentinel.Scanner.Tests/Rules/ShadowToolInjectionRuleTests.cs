using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class ShadowToolInjectionRuleTests
{
    private readonly ShadowToolInjectionRule _rule = new();

    private static ScanContext MakeContext(params (string server, string[] tools)[] servers)
    {
        return new ScanContext
        {
            Servers = [.. servers.Select(s => new ServerEnumeration
            {
                ServerConfig = new McpServerConfig { Name = s.server },
                ServerName = s.server,
                Transport = "stdio",
                ConnectionSuccessful = true,
                Tools = [.. s.tools.Select(t => new McpToolDefinition { Name = t, Description = "desc" })]
            })]
        };
    }

    [Fact]
    public async Task Evaluate_NoSimilarity_NoFindings()
    {
        var context = MakeContext(("s1", new[] { "weather", "calculator" }));
        var findings = await _rule.EvaluateAsync(context);
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_ExactMatchWithPrivileged_NoFinding()
    {
        var context = MakeContext(("s1", new[] { "read_file" }));
        var findings = await _rule.EvaluateAsync(context);

        findings.ShouldBeEmpty(); // Exact match is NOT shadowing, it IS the privileged tool
    }

    [Fact]
    public async Task Evaluate_TyposquatOfPrivilegedTool_ReturnsFinding()
    {
        // "raed_file" is 2 edits from "read_file"
        var context = MakeContext(("s1", new[] { "raed_file" }));
        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotBeEmpty();
        findings[0].RuleId.ShouldBe("SS-023");
        findings[0].Severity.ShouldBe(Severity.High);
    }

    [Fact]
    public async Task Evaluate_CrossServerTyposquat_ReturnsFinding()
    {
        // "calculate" and "calculat" are 1 edit apart across servers
        var context = MakeContext(
            ("s1", new[] { "calculate" }),
            ("s2", new[] { "calculat" }));

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.ShouldContain(f => f.Severity == Severity.Medium && f.Title.Contains("Typosquat", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Evaluate_ShortToolNames_SkippedToReduceNoise()
    {
        // Short names produce too many false matches at distance 1
        var context = MakeContext(("s1", new[] { "run" }));
        var findings = await _rule.EvaluateAsync(context);
        findings.ShouldBeEmpty();
    }
}
