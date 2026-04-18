using System;
using System.Collections.Generic;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Scoring;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Scoring;

/// <summary>
/// v2.3.0 fix (Section 0.4): reports should expose what the grade would be
/// if every suppression were removed, so users can see their technical-debt
/// exposure at a glance. The arithmetic sits in SeverityScorer.CalculateGrade
/// over (Findings + SuppressedFindings).
/// </summary>
public class GradeAttributionTests
{
    private static Finding Finding(Severity severity, string ruleId = "SS-011") => new()
    {
        RuleId = ruleId,
        OwaspCode = "ASI01",
        Severity = severity,
        Title = "t",
        Description = "d",
        Remediation = "r",
        ServerName = "sample",
        Confidence = 0.9
    };

    [Fact]
    public void NoSuppressions_GradesEqual()
    {
        var active = new List<Finding> { Finding(Severity.Medium) };
        var suppressed = new List<Finding>();

        var (liveGrade, liveScore) = SeverityScorer.CalculateGrade(active, System.Array.Empty<AttackPath>());

        var combined = new List<Finding>(active);
        combined.AddRange(suppressed);
        var (counterGrade, counterScore) = SeverityScorer.CalculateGrade(combined, System.Array.Empty<AttackPath>());

        Assert.Equal(liveGrade, counterGrade);
        Assert.Equal(liveScore, counterScore);
    }

    [Fact]
    public void SuppressionsCarryRealWeight_GradesDiverge()
    {
        // Active: 1 Medium -> high B/C grade
        // Suppressed: 2 Criticals -> would be F without suppression
        var active = new List<Finding> { Finding(Severity.Medium) };
        var suppressed = new List<Finding>
        {
            Finding(Severity.Critical),
            Finding(Severity.Critical)
        };

        var (liveGrade, liveScore) = SeverityScorer.CalculateGrade(active, System.Array.Empty<AttackPath>());

        var combined = new List<Finding>(active);
        combined.AddRange(suppressed);
        var (counterGrade, counterScore) = SeverityScorer.CalculateGrade(combined, System.Array.Empty<AttackPath>());

        Assert.True(liveScore > counterScore, $"Suppressions should improve live score; live={liveScore}, counter={counterScore}");
        Assert.True((int)counterGrade > (int)liveGrade, $"Counter-factual grade should be strictly worse; live={liveGrade}, counter={counterGrade}");
    }

    [Fact]
    public void ScanResult_PopulatesWithAndWithoutSuppressionFields()
    {
        var result = new ScanResult
        {
            ScanTimestamp = DateTimeOffset.UtcNow,
            ScannerVersion = "2.3.0",
            Servers = System.Array.Empty<ServerScanSummary>(),
            Findings = System.Array.Empty<Finding>(),
            AttackPaths = System.Array.Empty<AttackPath>(),
            Grade = SecurityGrade.A,
            Score = 100,
            Statistics = new ScanStatistics(),
            SuppressedFindings = new[] { Finding(Severity.High), Finding(Severity.Critical) },
            GradeWithoutSuppressions = SecurityGrade.F,
            ScoreWithoutSuppressions = 25
        };

        Assert.Equal(SecurityGrade.A, result.Grade);
        Assert.Equal(SecurityGrade.F, result.GradeWithoutSuppressions);
        Assert.Equal(100, result.Score);
        Assert.Equal(25, result.ScoreWithoutSuppressions);
    }
}
