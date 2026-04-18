using System;
using System.Collections.Generic;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.History;
using Xunit;

namespace SignalSentinel.Scanner.Tests.History;

public class ScanDifferTests
{
    private static Finding MakeFinding(string ruleId, string server, string? tool, string? evidence, Severity severity)
    {
        return new Finding
        {
            RuleId = ruleId,
            OwaspCode = "ASI01",
            Severity = severity,
            Title = "t",
            Description = "d",
            Remediation = "r",
            ServerName = server,
            ToolName = tool,
            Evidence = evidence
        };
    }

    private static ScanResult MakeResult(IReadOnlyList<Finding> findings, SecurityGrade grade, int score)
    {
        return new ScanResult
        {
            ScanTimestamp = DateTimeOffset.UtcNow,
            ScannerVersion = "2.3.0",
            Servers = Array.Empty<ServerScanSummary>(),
            Findings = findings,
            AttackPaths = Array.Empty<AttackPath>(),
            Grade = grade,
            Score = score,
            Statistics = new ScanStatistics()
        };
    }

    [Fact]
    public void Compute_IdenticalScans_ProducesEmptyDiff()
    {
        var findings = new[] { MakeFinding("SS-001", "srv", null, "e", Severity.High) };
        var result = MakeResult(findings, SecurityGrade.C, 75);
        var diff = ScanDiffer.Compute(result, result);
        Assert.Empty(diff.Added);
        Assert.Empty(diff.Resolved);
        Assert.Single(diff.Unchanged);
    }

    [Fact]
    public void Compute_RegressionOnly_ProducesAddedOnly()
    {
        var baseline = MakeResult(Array.Empty<Finding>(), SecurityGrade.A, 100);
        var current = MakeResult(new[]
        {
            MakeFinding("SS-014", "srv", null, "fetch(", Severity.Critical)
        }, SecurityGrade.D, 70);
        var diff = ScanDiffer.Compute(baseline, current);
        Assert.Single(diff.Added);
        Assert.Empty(diff.Resolved);
    }

    [Fact]
    public void Compute_RemediationOnly_ProducesResolvedOnly()
    {
        var baseline = MakeResult(new[]
        {
            MakeFinding("SS-014", "srv", null, "fetch(", Severity.Critical)
        }, SecurityGrade.D, 70);
        var current = MakeResult(Array.Empty<Finding>(), SecurityGrade.A, 100);
        var diff = ScanDiffer.Compute(baseline, current);
        Assert.Empty(diff.Added);
        Assert.Single(diff.Resolved);
    }

    [Fact]
    public void Compute_AttributesPointsByRule()
    {
        var baseline = MakeResult(Array.Empty<Finding>(), SecurityGrade.A, 100);
        var current = MakeResult(new[]
        {
            MakeFinding("SS-014", "srv", null, "fetch(", Severity.Critical),
            MakeFinding("SS-022", "srv", null, "mutation", Severity.High)
        }, SecurityGrade.D, 55);
        var diff = ScanDiffer.Compute(baseline, current);
        Assert.Equal(-30, diff.AddedContribution["SS-014"]);
        Assert.Equal(-15, diff.AddedContribution["SS-022"]);
    }

    [Fact]
    public void Compute_IdentityKeyDifferentiatesByEvidence()
    {
        var baseline = MakeResult(new[]
        {
            MakeFinding("SS-016", "srv", null, "/root/a", Severity.Medium)
        }, SecurityGrade.C, 80);
        var current = MakeResult(new[]
        {
            MakeFinding("SS-016", "srv", null, "/root/b", Severity.Medium)
        }, SecurityGrade.C, 80);
        var diff = ScanDiffer.Compute(baseline, current);
        Assert.Single(diff.Added);
        Assert.Single(diff.Resolved);
        Assert.Empty(diff.Unchanged);
    }
}
