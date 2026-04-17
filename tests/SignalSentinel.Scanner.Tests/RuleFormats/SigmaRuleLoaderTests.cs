using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.RuleFormats;
using Xunit;

namespace SignalSentinel.Scanner.Tests.RuleFormats;

public class SigmaRuleLoaderTests
{
    [Fact]
    public void Parse_ValidSigmaRule_ReturnsRule()
    {
        var yaml = """
        title: Detect AWS Access Key Leakage
        id: 550e8400-e29b-41d4-a716-446655440000
        description: Flags descriptions containing AWS access keys
        level: high
        tags:
          - attack.credential_access
          - owasp.asi03
        logsource:
          product: mcp
          category: tool
        detection:
          selection:
            description|contains:
              - 'AKIA'
              - 'aws_access_key_id'
          condition: selection
        """;

        var rule = SigmaRuleLoader.Parse(yaml);

        rule.ShouldNotBeNull();
        rule!.Title.ShouldBe("Detect AWS Access Key Leakage");
        rule.Level.ShouldBe(Severity.High);
        rule.Product.ShouldBe("mcp");
        rule.Patterns.Count.ShouldBe(2);
        rule.Patterns.ShouldContain(p => p.Value == "AKIA" && p.MatchType == SigmaMatchType.Contains);
    }

    [Fact]
    public void Parse_MissingTitle_ReturnsNull()
    {
        var yaml = """
        id: test
        level: low
        detection:
          selection:
            description: test
          condition: selection
        """;

        var rule = SigmaRuleLoader.Parse(yaml);
        rule.ShouldBeNull();
    }

    [Fact]
    public void Parse_MissingDetection_ReturnsNull()
    {
        var yaml = """
        title: No Detection
        id: test
        """;

        var rule = SigmaRuleLoader.Parse(yaml);
        rule.ShouldBeNull();
    }

    [Theory]
    [InlineData("informational", Severity.Info)]
    [InlineData("low", Severity.Low)]
    [InlineData("medium", Severity.Medium)]
    [InlineData("high", Severity.High)]
    [InlineData("critical", Severity.Critical)]
    public void Parse_LevelMapping_MapsCorrectly(string level, Severity expected)
    {
        var yaml = $"""
        title: test
        level: {level}
        detection:
          selection:
            description: test
          condition: selection
        """;

        var rule = SigmaRuleLoader.Parse(yaml);

        rule.ShouldNotBeNull();
        rule!.Level.ShouldBe(expected);
    }

    [Fact]
    public void Parse_NoLevel_DefaultsToMedium()
    {
        var yaml = """
        title: test
        detection:
          selection:
            description|contains: foo
          condition: selection
        """;

        var rule = SigmaRuleLoader.Parse(yaml);

        rule.ShouldNotBeNull();
        rule!.Level.ShouldBe(Severity.Medium);
    }

    [Theory]
    [InlineData("description|contains", SigmaMatchType.Contains)]
    [InlineData("description|startswith", SigmaMatchType.StartsWith)]
    [InlineData("description|endswith", SigmaMatchType.EndsWith)]
    [InlineData("description", SigmaMatchType.Equals)]
    public void Parse_MatchTypeModifiers_ExtractCorrectly(string fieldKey, SigmaMatchType expected)
    {
        var yaml = $"""
        title: Modifier Test
        detection:
          selection:
            {fieldKey}: payload
          condition: selection
        """;

        var rule = SigmaRuleLoader.Parse(yaml);

        rule.ShouldNotBeNull();
        rule!.Patterns[0].MatchType.ShouldBe(expected);
    }
}
