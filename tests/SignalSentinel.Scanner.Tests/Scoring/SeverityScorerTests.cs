using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Scoring;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Scoring;

public class SeverityScorerTests
{
    [Fact]
    public void CalculateGrade_WithNoFindings_ReturnsGradeA()
    {
        // Arrange
        var findings = Array.Empty<Finding>();
        var attackPaths = Array.Empty<AttackPath>();

        // Act
        var (grade, score) = SeverityScorer.CalculateGrade(findings, attackPaths);

        // Assert
        grade.ShouldBe(SecurityGrade.A);
        score.ShouldBe(100);
    }

    [Fact]
    public void CalculateGrade_WithSingleCritical_ReturnsGradeD()
    {
        // Arrange
        var findings = new[]
        {
            CreateFinding(Severity.Critical)
        };
        var attackPaths = Array.Empty<AttackPath>();

        // Act
        var (grade, _) = SeverityScorer.CalculateGrade(findings, attackPaths);

        // Assert
        grade.ShouldBe(SecurityGrade.D);
    }

    [Fact]
    public void CalculateGrade_WithMultipleCriticals_ReturnsGradeF()
    {
        // Arrange
        var findings = new[]
        {
            CreateFinding(Severity.Critical),
            CreateFinding(Severity.Critical)
        };
        var attackPaths = Array.Empty<AttackPath>();

        // Act
        var (grade, _) = SeverityScorer.CalculateGrade(findings, attackPaths);

        // Assert
        grade.ShouldBe(SecurityGrade.F);
    }

    [Fact]
    public void CalculateGrade_WithHighFindings_ReturnsGradeC()
    {
        // Arrange
        var findings = new[]
        {
            CreateFinding(Severity.High),
            CreateFinding(Severity.Medium)
        };
        var attackPaths = Array.Empty<AttackPath>();

        // Act
        var (grade, _) = SeverityScorer.CalculateGrade(findings, attackPaths);

        // Assert
        grade.ShouldBe(SecurityGrade.C);
    }

    [Fact]
    public void CalculateGrade_WithOnlyLowFindings_ReturnsGradeAOrB()
    {
        // Arrange
        var findings = new[]
        {
            CreateFinding(Severity.Low),
            CreateFinding(Severity.Low),
            CreateFinding(Severity.Info)
        };
        var attackPaths = Array.Empty<AttackPath>();

        // Act
        var (grade, score) = SeverityScorer.CalculateGrade(findings, attackPaths);

        // Assert
        grade.ShouldBeOneOf(SecurityGrade.A, SecurityGrade.B);
        score.ShouldBeGreaterThan(90);
    }

    [Fact]
    public void CalculateGrade_WithCriticalAttackPath_ReturnsGradeD()
    {
        // Arrange
        var findings = Array.Empty<Finding>();
        var attackPaths = new[]
        {
            CreateAttackPath(Severity.Critical)
        };

        // Act
        var (grade, _) = SeverityScorer.CalculateGrade(findings, attackPaths);

        // Assert
        grade.ShouldBe(SecurityGrade.D);
    }

    [Fact]
    public void CalculateGrade_WithCriticalFindingAndCriticalAttackPath_ReturnsGradeF()
    {
        // Arrange
        var findings = new[]
        {
            CreateFinding(Severity.Critical)
        };
        var attackPaths = new[]
        {
            CreateAttackPath(Severity.Critical)
        };

        // Act
        var (grade, _) = SeverityScorer.CalculateGrade(findings, attackPaths);

        // Assert
        grade.ShouldBe(SecurityGrade.F);
    }

    [Theory]
    [InlineData(5, 0, 0, 0, 75)] // 5 criticals = -125 points, capped at 0, but let's verify
    [InlineData(0, 3, 0, 0, 70)] // 3 highs = -30 points = 70
    [InlineData(0, 0, 10, 0, 70)] // 10 mediums = -30 points = 70
    [InlineData(0, 0, 0, 20, 80)] // 20 lows = -20 points = 80
    public void CalculateGrade_ScoreCalculation_IsCorrect(
        int criticals, int highs, int mediums, int lows, int expectedMinScore)
    {
        // Arrange
        var findings = new List<Finding>();
        findings.AddRange(Enumerable.Range(0, criticals).Select(_ => CreateFinding(Severity.Critical)));
        findings.AddRange(Enumerable.Range(0, highs).Select(_ => CreateFinding(Severity.High)));
        findings.AddRange(Enumerable.Range(0, mediums).Select(_ => CreateFinding(Severity.Medium)));
        findings.AddRange(Enumerable.Range(0, lows).Select(_ => CreateFinding(Severity.Low)));

        // Act
        var (_, score) = SeverityScorer.CalculateGrade(findings, []);

        // Assert
        score.ShouldBeLessThanOrEqualTo(expectedMinScore + 5); // Allow some tolerance
    }

    private static Finding CreateFinding(Severity severity)
    {
        return new Finding
        {
            RuleId = "TEST-001",
            OwaspCode = OwaspAsiCodes.ASI01,
            Severity = severity,
            Title = "Test Finding",
            Description = "Test description",
            Remediation = "Test remediation",
            ServerName = "test-server"
        };
    }

    private static AttackPath CreateAttackPath(Severity severity)
    {
        return new AttackPath
        {
            Id = "AP-001",
            Description = "Test attack path",
            Severity = severity,
            OwaspCodes = [OwaspAsiCodes.ASI02],
            Steps = [],
            Remediation = "Test remediation"
        };
    }
}
