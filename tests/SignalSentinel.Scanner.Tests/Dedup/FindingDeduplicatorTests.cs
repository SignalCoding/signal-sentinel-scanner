using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Dedup;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Dedup;

public class FindingDeduplicatorTests
{
    private static Finding MakeFinding(string ruleId, string server, string? tool, string? evidence, Severity severity = Severity.Medium)
    {
        return new Finding
        {
            RuleId = ruleId,
            OwaspCode = "ASI01",
            Severity = severity,
            Title = $"{ruleId} finding",
            Description = "Test finding",
            Remediation = "Fix it",
            ServerName = server,
            ToolName = tool,
            Evidence = evidence
        };
    }

    [Fact]
    public void Deduplicate_EmptyList_ReturnsEmpty()
    {
        var result = FindingDeduplicator.Deduplicate([]);
        result.ShouldBeEmpty();
    }

    [Fact]
    public void Deduplicate_DistinctFindings_ReturnsAllUnchanged()
    {
        var findings = new[]
        {
            MakeFinding("SS-001", "serverA", "toolA", "evidence1"),
            MakeFinding("SS-002", "serverA", "toolB", "evidence2")
        };

        var result = FindingDeduplicator.Deduplicate(findings);

        result.Count.ShouldBe(2);
        result.ShouldAllBe(f => f.OccurrenceCount == 1);
    }

    [Fact]
    public void Deduplicate_IdenticalFindings_CollapsesWithOccurrenceCount()
    {
        var findings = new[]
        {
            MakeFinding("SS-001", "serverA", "toolA", "evidence1"),
            MakeFinding("SS-001", "serverA", "toolA", "evidence1"),
            MakeFinding("SS-001", "serverA", "toolA", "evidence1")
        };

        var result = FindingDeduplicator.Deduplicate(findings);

        result.Count.ShouldBe(1);
        result[0].OccurrenceCount.ShouldBe(3);
    }

    [Fact]
    public void Deduplicate_DifferentEvidence_KeepsBothFindings()
    {
        var findings = new[]
        {
            MakeFinding("SS-001", "serverA", "toolA", "evidence1"),
            MakeFinding("SS-001", "serverA", "toolA", "evidence2")
        };

        var result = FindingDeduplicator.Deduplicate(findings);

        result.Count.ShouldBe(2);
    }

    [Fact]
    public void Deduplicate_RetainsHighestSeverityWhenCollapsing()
    {
        var findings = new[]
        {
            MakeFinding("SS-001", "serverA", "toolA", "evidence1", Severity.Low),
            MakeFinding("SS-001", "serverA", "toolA", "evidence1", Severity.Critical),
            MakeFinding("SS-001", "serverA", "toolA", "evidence1", Severity.Medium)
        };

        var result = FindingDeduplicator.Deduplicate(findings);

        result.Count.ShouldBe(1);
        result[0].Severity.ShouldBe(Severity.Critical);
        result[0].OccurrenceCount.ShouldBe(3);
    }

    [Fact]
    public void Deduplicate_PreservesInsertionOrder()
    {
        var findings = new[]
        {
            MakeFinding("SS-003", "serverA", "toolA", "e1"),
            MakeFinding("SS-001", "serverA", "toolA", "e1"),
            MakeFinding("SS-002", "serverA", "toolA", "e1")
        };

        var result = FindingDeduplicator.Deduplicate(findings);

        result.Select(f => f.RuleId).ShouldBe(["SS-003", "SS-001", "SS-002"]);
    }
}
