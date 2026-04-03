using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Scoring;

/// <summary>
/// Maps and aggregates findings by OWASP Agentic AI Security codes.
/// </summary>
public static class OwaspMapper
{
    /// <summary>
    /// Groups findings by OWASP ASI code.
    /// </summary>
    public static IReadOnlyDictionary<string, OwaspCategorySummary> GroupByOwaspCode(
        IReadOnlyList<Finding> findings)
    {
        var allCodes = new[]
        {
            OwaspAsiCodes.ASI01, OwaspAsiCodes.ASI02, OwaspAsiCodes.ASI03,
            OwaspAsiCodes.ASI04, OwaspAsiCodes.ASI05, OwaspAsiCodes.ASI06,
            OwaspAsiCodes.ASI07, OwaspAsiCodes.ASI08, OwaspAsiCodes.ASI09,
            OwaspAsiCodes.ASI10
        };

        var result = new Dictionary<string, OwaspCategorySummary>();

        foreach (var code in allCodes)
        {
            var categoryFindings = findings.Where(f => f.OwaspCode == code).ToList();

            result[code] = new OwaspCategorySummary
            {
                Code = code,
                Description = OwaspAsiCodes.GetDescription(code),
                DocumentationUrl = OwaspAsiCodes.GetDocumentationUrl(code),
                TotalFindings = categoryFindings.Count,
                CriticalCount = categoryFindings.Count(f => f.Severity == Severity.Critical),
                HighCount = categoryFindings.Count(f => f.Severity == Severity.High),
                MediumCount = categoryFindings.Count(f => f.Severity == Severity.Medium),
                LowCount = categoryFindings.Count(f => f.Severity == Severity.Low),
                InfoCount = categoryFindings.Count(f => f.Severity == Severity.Info),
                MaxSeverity = categoryFindings.Count > 0
                    ? categoryFindings.Max(f => f.Severity)
                    : null,
                Findings = categoryFindings
            };
        }

        return result;
    }

    /// <summary>
    /// Calculates OWASP coverage score (percentage of categories without critical/high findings).
    /// </summary>
    public static double CalculateCoverageScore(IReadOnlyDictionary<string, OwaspCategorySummary> categories)
    {
        var totalCategories = categories.Count;
        if (totalCategories == 0)
        {
            return 100.0;
        }

        var coveredCategories = categories.Values
            .Count(c => c.CriticalCount == 0 && c.HighCount == 0);

        return (double)coveredCategories / totalCategories * 100.0;
    }

    /// <summary>
    /// Generates a compliance matrix for the scan result.
    /// </summary>
    public static IReadOnlyList<ComplianceMatrixRow> GenerateComplianceMatrix(
        IReadOnlyDictionary<string, OwaspCategorySummary> categories)
    {
        return categories.Values
            .OrderBy(c => c.Code)
            .Select(c => new ComplianceMatrixRow
            {
                Code = c.Code,
                Description = c.Description,
                Status = DetermineComplianceStatus(c),
                FindingsCount = c.TotalFindings,
                MaxSeverity = c.MaxSeverity,
                Recommendation = GetRecommendation(c)
            })
            .ToList();
    }

    private static ComplianceStatus DetermineComplianceStatus(OwaspCategorySummary category)
    {
        if (category.CriticalCount > 0)
        {
            return ComplianceStatus.NonCompliant;
        }

        if (category.HighCount > 0)
        {
            return ComplianceStatus.PartiallyCompliant;
        }

        if (category.MediumCount > 0)
        {
            return ComplianceStatus.NeedsImprovement;
        }

        if (category.TotalFindings > 0)
        {
            return ComplianceStatus.Compliant;
        }

        return ComplianceStatus.FullyCompliant;
    }

    private static string GetRecommendation(OwaspCategorySummary category)
    {
        if (category.CriticalCount > 0)
        {
            return $"URGENT: {category.CriticalCount} critical finding(s) require immediate remediation.";
        }

        if (category.HighCount > 0)
        {
            return $"HIGH PRIORITY: {category.HighCount} high severity finding(s) require prompt attention.";
        }

        if (category.MediumCount > 0)
        {
            return $"Review {category.MediumCount} medium severity finding(s) and address as part of regular maintenance.";
        }

        if (category.TotalFindings > 0)
        {
            return $"Minor issues detected. Consider addressing {category.TotalFindings} low/info finding(s) when convenient.";
        }

        return "No issues detected for this category.";
    }
}

/// <summary>
/// Summary of findings for a single OWASP ASI category.
/// </summary>
public sealed record OwaspCategorySummary
{
    public required string Code { get; init; }
    public required string Description { get; init; }
    public required string DocumentationUrl { get; init; }
    public int TotalFindings { get; init; }
    public int CriticalCount { get; init; }
    public int HighCount { get; init; }
    public int MediumCount { get; init; }
    public int LowCount { get; init; }
    public int InfoCount { get; init; }
    public Severity? MaxSeverity { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
}

/// <summary>
/// Compliance status for OWASP categories.
/// </summary>
public enum ComplianceStatus
{
    FullyCompliant,
    Compliant,
    NeedsImprovement,
    PartiallyCompliant,
    NonCompliant
}

/// <summary>
/// A row in the compliance matrix.
/// </summary>
public sealed record ComplianceMatrixRow
{
    public required string Code { get; init; }
    public required string Description { get; init; }
    public required ComplianceStatus Status { get; init; }
    public int FindingsCount { get; init; }
    public Severity? MaxSeverity { get; init; }
    public required string Recommendation { get; init; }
}
