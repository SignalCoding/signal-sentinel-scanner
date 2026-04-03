using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Scoring;

/// <summary>
/// Calculates security scores and grades based on findings.
/// </summary>
public static class SeverityScorer
{
    /// <summary>
    /// Calculates an overall security grade based on findings and attack paths.
    /// </summary>
    public static (SecurityGrade Grade, int Score) CalculateGrade(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<AttackPath> attackPaths)
    {
        var criticalCount = findings.Count(f => f.Severity == Severity.Critical);
        var highCount = findings.Count(f => f.Severity == Severity.High);
        var mediumCount = findings.Count(f => f.Severity == Severity.Medium);
        var lowCount = findings.Count(f => f.Severity == Severity.Low);
        var criticalAttackPaths = attackPaths.Count(p => p.Severity == Severity.Critical);
        var highAttackPaths = attackPaths.Count(p => p.Severity == Severity.High);

        // Start with perfect score
        var score = 100;

        // Deduct points based on findings
        score -= criticalCount * 25;
        score -= highCount * 10;
        score -= mediumCount * 3;
        score -= lowCount * 1;

        // Deduct points for attack paths
        score -= criticalAttackPaths * 20;
        score -= highAttackPaths * 10;

        // Ensure score is within bounds
        score = Math.Max(0, Math.Min(100, score));

        // Determine grade
        var grade = DetermineGrade(criticalCount, highCount, criticalAttackPaths, highAttackPaths, score);

        return (grade, score);
    }

    private static SecurityGrade DetermineGrade(
        int criticalCount,
        int highCount,
        int criticalAttackPaths,
        int highAttackPaths,
        int score)
    {
        // F: Multiple critical findings or high-severity attack paths
        if (criticalCount >= 2 || criticalAttackPaths >= 2 || (criticalCount >= 1 && criticalAttackPaths >= 1))
        {
            return SecurityGrade.F;
        }

        // D: Critical findings present
        if (criticalCount >= 1 || criticalAttackPaths >= 1)
        {
            return SecurityGrade.D;
        }

        // C: 1-2 high findings or 1 attack path
        if (highCount >= 1 || highAttackPaths >= 1)
        {
            return SecurityGrade.C;
        }

        // B: No critical findings, some issues but score is still decent
        if (score >= 70 && score < 90)
        {
            return SecurityGrade.B;
        }

        // A: No critical/high findings, good score
        if (score >= 90)
        {
            return SecurityGrade.A;
        }

        return score >= 50 ? SecurityGrade.C : SecurityGrade.D;
    }

    /// <summary>
    /// Gets a human-readable description of the grade.
    /// </summary>
    public static string GetGradeDescription(SecurityGrade grade) => grade switch
    {
        SecurityGrade.A => "Excellent - No critical or high severity findings. MCP configuration follows security best practices.",
        SecurityGrade.B => "Good - No critical findings. Minor improvements recommended.",
        SecurityGrade.C => "Fair - Some high severity findings present. Review and remediation recommended.",
        SecurityGrade.D => "Poor - Critical findings detected. Immediate remediation required.",
        SecurityGrade.F => "Failing - Multiple critical findings or attack paths. Do not use in production.",
        _ => "Unknown grade"
    };

    /// <summary>
    /// Gets a color code for the grade (for HTML reports).
    /// </summary>
    public static string GetGradeColor(SecurityGrade grade) => grade switch
    {
        SecurityGrade.A => "#22c55e", // Green
        SecurityGrade.B => "#84cc16", // Lime
        SecurityGrade.C => "#eab308", // Yellow
        SecurityGrade.D => "#f97316", // Orange
        SecurityGrade.F => "#ef4444", // Red
        _ => "#6b7280"  // Gray
    };

    /// <summary>
    /// Gets a color code for a severity level.
    /// </summary>
    public static string GetSeverityColor(Severity severity) => severity switch
    {
        Severity.Critical => "#ef4444", // Red
        Severity.High => "#f97316",     // Orange
        Severity.Medium => "#eab308",   // Yellow
        Severity.Low => "#22c55e",      // Green
        Severity.Info => "#3b82f6",     // Blue
        _ => "#6b7280"                   // Gray
    };
}
