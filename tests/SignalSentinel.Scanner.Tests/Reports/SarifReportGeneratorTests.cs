using System.Text.Json;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Reports;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Reports;

public class SarifReportGeneratorTests
{
    private readonly SarifReportGenerator _generator = new();

    private static ScanResult MakeResult(params Finding[] findings)
    {
        return new ScanResult
        {
            ScanTimestamp = DateTimeOffset.UtcNow,
            ScannerVersion = "2.2.0",
            Servers = [],
            Findings = findings,
            AttackPaths = [],
            Grade = SecurityGrade.A,
            Score = 100,
            Statistics = new ScanStatistics()
        };
    }

    private static Finding MakeFinding(string ruleId, Severity severity, string server, string? tool = null) =>
        new()
        {
            RuleId = ruleId,
            OwaspCode = "ASI01",
            McpCode = "MCP01",
            Severity = severity,
            Title = "Test",
            Description = "Test description",
            Remediation = "Fix it",
            ServerName = server,
            ToolName = tool,
            Evidence = "evidence"
        };

    [Fact]
    public void Generate_ProducesValidJson()
    {
        var result = MakeResult(MakeFinding("SS-001", Severity.High, "s1", "t1"));

        var sarif = _generator.Generate(result);

        var doc = JsonDocument.Parse(sarif);
        doc.RootElement.GetProperty("version").GetString().ShouldBe("2.1.0");
        doc.RootElement.GetProperty("runs").GetArrayLength().ShouldBe(1);
    }

    [Fact]
    public void Generate_IncludesSchemaReference()
    {
        var result = MakeResult();

        var sarif = _generator.Generate(result);

        var doc = JsonDocument.Parse(sarif);
        var schema = doc.RootElement.GetProperty("$schema").GetString();
        schema.ShouldNotBeNull();
        schema.ShouldContain("sarif");
    }

    [Fact]
    public void Generate_ToolDriverIncludesAllRulesFromFindings()
    {
        var result = MakeResult(
            MakeFinding("SS-001", Severity.High, "s1"),
            MakeFinding("SS-002", Severity.Low, "s1"),
            MakeFinding("SS-001", Severity.High, "s2"));

        var sarif = _generator.Generate(result);

        var doc = JsonDocument.Parse(sarif);
        var rules = doc.RootElement.GetProperty("runs")[0]
            .GetProperty("tool").GetProperty("driver").GetProperty("rules");

        rules.GetArrayLength().ShouldBe(2);
    }

    [Theory]
    [InlineData(Severity.Critical, "error")]
    [InlineData(Severity.High, "error")]
    [InlineData(Severity.Medium, "warning")]
    [InlineData(Severity.Low, "note")]
    [InlineData(Severity.Info, "note")]
    public void Generate_MapsSeverityToSarifLevel(Severity severity, string expectedLevel)
    {
        var result = MakeResult(MakeFinding("SS-001", severity, "s1"));

        var sarif = _generator.Generate(result);

        var doc = JsonDocument.Parse(sarif);
        var level = doc.RootElement.GetProperty("runs")[0]
            .GetProperty("results")[0].GetProperty("level").GetString();

        level.ShouldBe(expectedLevel);
    }

    [Fact]
    public void Generate_IncludesSecurityGradeInRunProperties()
    {
        var result = new ScanResult
        {
            ScanTimestamp = DateTimeOffset.UtcNow,
            ScannerVersion = "2.2.0",
            Servers = [],
            Findings = [],
            AttackPaths = [],
            Grade = SecurityGrade.B,
            Score = 85,
            Statistics = new ScanStatistics()
        };

        var sarif = _generator.Generate(result);

        var doc = JsonDocument.Parse(sarif);
        var props = doc.RootElement.GetProperty("runs")[0].GetProperty("properties");
        props.GetProperty("securityGrade").GetString().ShouldBe("B");
        props.GetProperty("securityScore").GetInt32().ShouldBe(85);
    }

    [Fact]
    public void Generate_SkillFindingHasSkillKindLocation()
    {
        var finding = MakeFinding("SS-024", Severity.Medium, "skill-name") with
        {
            Source = FindingSource.Skill,
            SkillFilePath = "/path/to/SKILL.md"
        };
        var result = MakeResult(finding);

        var sarif = _generator.Generate(result);

        var doc = JsonDocument.Parse(sarif);
        var loc = doc.RootElement.GetProperty("runs")[0].GetProperty("results")[0]
            .GetProperty("locations")[0].GetProperty("logicalLocations")[0];
        loc.GetProperty("kind").GetString().ShouldBe("skill");
    }
}
