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
    /// <param name="findings">All findings from the scan.</param>
    /// <param name="attackPaths">All attack paths from the scan.</param>
    /// <param name="totalServers">
    /// v2.4.1 (G1): total servers configured/discovered for this scan (regardless of
    /// connection success). When supplied together with <paramref name="totalSkills"/>
    /// as both zero, the grade is <see cref="SecurityGrade.Inconclusive"/> instead of
    /// the finding-count-driven grade, because the scan evaluated no scannable surface
    /// at all. Pass <see langword="null"/> to preserve pre-v2.4.1 behaviour (used by
    /// existing tests/call sites that don't have this context).
    /// </param>
    /// <param name="totalSkills">See <paramref name="totalServers"/>.</param>
    /// <param name="rubric">
    /// v3.0.0 (WP11): the scoring rubric supplying deductions, grade-rule counts and
    /// grade thresholds. Defaults to the embedded <see cref="ScoringRubric.Default"/>
    /// (v2.0.0, weights identical to the hard-coded v2.x algorithm); the CLI passes a
    /// custom rubric here when <c>--rubric &lt;path&gt;</c> is given.
    /// </param>
    public static (SecurityGrade Grade, int Score) CalculateGrade(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<AttackPath> attackPaths,
        int? totalServers = null,
        int? totalSkills = null,
        ScoringRubric? rubric = null)
    {
        rubric ??= ScoringRubric.Default;

        // v2.4.1 (G1): a scan that evaluated no scannable surface (no servers AND no
        // skills) previously fell through to the finding-count-driven algorithm below,
        // which - having zero findings by construction - always returned Grade A
        // (99-100/100). A naive CI pipeline that mistypes a --remote URL, or that runs
        // with no config and no --skills, would then see a green "Grade A" instead of
        // being told the scan didn't evaluate anything.
        if (totalServers == 0 && totalSkills == 0)
        {
            return (SecurityGrade.Inconclusive, 0);
        }

        // v2.4.0 (G7): dormant findings (tagged Scope == "dormant" by ScopeManager)
        // are retained in reports for audit trail but do not contribute to the grade.
        // They represent findings against skills/servers that are not part of the
        // live attack surface at the orchestrator level, so counting them would
        // overstate real risk.
        var scored = findings
            .Where(f => !string.Equals(f.Scope, "dormant", StringComparison.Ordinal))
            .ToList();

        var criticalCount = scored.Count(f => f.Severity == Severity.Critical);
        var highCount = scored.Count(f => f.Severity == Severity.High);
        var mediumCount = scored.Count(f => f.Severity == Severity.Medium);
        var lowCount = scored.Count(f => f.Severity == Severity.Low);
        var criticalAttackPaths = attackPaths.Count(p => p.Severity == Severity.Critical);
        var highAttackPaths = attackPaths.Count(p => p.Severity == Severity.High);

        // Start with perfect score
        var score = 100;
        var deductions = rubric.Deductions;

        // Deduct points based on findings
        score -= criticalCount * deductions.CriticalFinding;
        score -= highCount * deductions.HighFinding;
        score -= mediumCount * deductions.MediumFinding;
        score -= lowCount * deductions.LowFinding;

        // Deduct points for attack paths
        score -= criticalAttackPaths * deductions.CriticalAttackPath;
        score -= highAttackPaths * deductions.HighAttackPath;

        // Ensure score is within bounds
        score = Math.Max(0, Math.Min(100, score));

        // Determine grade
        var grade = DetermineGrade(rubric, criticalCount, highCount, criticalAttackPaths, highAttackPaths, score);

        return (grade, score);
    }

    private static SecurityGrade DetermineGrade(
        ScoringRubric rubric,
        int criticalCount,
        int highCount,
        int criticalAttackPaths,
        int highAttackPaths,
        int score)
    {
        var rules = rubric.GradeRules;
        var thresholds = rubric.GradeThresholds;

        // F: multiple critical findings or critical attack paths, or one of each
        // (the co-occurrence clause uses the D thresholds: any critical on both axes).
        if (criticalCount >= rules.F.CriticalFindingsAtLeast
            || criticalAttackPaths >= rules.F.CriticalAttackPathsAtLeast
            || (criticalCount >= rules.D.CriticalFindingsAtLeast
                && criticalAttackPaths >= rules.D.CriticalAttackPathsAtLeast))
        {
            return SecurityGrade.F;
        }

        // D: critical findings present
        if (criticalCount >= rules.D.CriticalFindingsAtLeast
            || criticalAttackPaths >= rules.D.CriticalAttackPathsAtLeast)
        {
            return SecurityGrade.D;
        }

        // C: high findings or a high attack path - but never better than the score
        // band (v3.0.2, N5, owner ruling option B): a High-bearing scan whose score
        // has collapsed below thresholds.C grades D instead of a flat C.
        if (highCount >= rules.C.HighFindingsAtLeast
            || highAttackPaths >= rules.C.HighAttackPathsAtLeast)
        {
            return score >= thresholds.C ? SecurityGrade.C : SecurityGrade.D;
        }

        // B: No critical findings, some issues but score is still decent
        if (score >= thresholds.B && score < thresholds.A)
        {
            return SecurityGrade.B;
        }

        // A: No critical/high findings, good score
        if (score >= thresholds.A)
        {
            return SecurityGrade.A;
        }

        return score >= thresholds.C ? SecurityGrade.C : SecurityGrade.D;
    }

    /// <summary>
    /// Gets a human-readable description of the grade.
    /// </summary>
    public static string GetGradeDescription(SecurityGrade grade) => grade switch
    {
        SecurityGrade.A => "Excellent - No critical or high severity findings. MCP configuration follows security best practices.",
        SecurityGrade.B => "Good - No critical findings. Minor improvements recommended.",
        SecurityGrade.C => "Fair - Some high severity findings present. Review and remediation recommended.",
        SecurityGrade.D => "Poor - Critical findings detected, or the score fell below the C threshold. Immediate remediation required.",
        SecurityGrade.F => "Failing - Multiple critical findings or attack paths. Do not use in production.",
        SecurityGrade.Inconclusive => "Scan produced no evaluable surface - no server connected and no skills were scanned. Check the connection errors and informational findings in this report and your --config/--remote/--skills arguments; this is not a security posture result.",
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
        SecurityGrade.Inconclusive => "#6b7280", // Gray - deliberately not green/red
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
