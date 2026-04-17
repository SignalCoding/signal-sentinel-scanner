// -----------------------------------------------------------------------
// <copyright file="FindingDeduplicator.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Dedup;

/// <summary>
/// Collapses findings that share the same (RuleId, ServerName, ToolName, Evidence) tuple.
/// Retains the highest-severity instance and records the occurrence count.
/// </summary>
/// <remarks>
/// Introduced in v2.2.0 to reduce report noise where a single underlying issue
/// produces multiple identical matches (common with pattern-based skill scanning).
/// </remarks>
public static class FindingDeduplicator
{
    /// <summary>
    /// Returns a deduplicated finding list with <see cref="Finding.OccurrenceCount"/> populated.
    /// Preserves original order of first-seen findings.
    /// </summary>
    /// <param name="findings">Findings produced by rule execution.</param>
    /// <returns>Deduplicated findings.</returns>
    public static IReadOnlyList<Finding> Deduplicate(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (findings.Count == 0)
        {
            return findings;
        }

        var seen = new Dictionary<string, (Finding Finding, int Count, int Index)>(StringComparer.Ordinal);
        var order = new List<string>(findings.Count);

        for (var i = 0; i < findings.Count; i++)
        {
            var finding = findings[i];
            var key = BuildKey(finding);

            if (seen.TryGetValue(key, out var existing))
            {
                // Retain the higher-severity instance if different
                var retained = finding.Severity > existing.Finding.Severity ? finding : existing.Finding;
                seen[key] = (retained, existing.Count + 1, existing.Index);
            }
            else
            {
                seen[key] = (finding, 1, order.Count);
                order.Add(key);
            }
        }

        var result = new List<Finding>(seen.Count);
        foreach (var key in order)
        {
            var (finding, count, _) = seen[key];
            result.Add(finding with { OccurrenceCount = count });
        }

        return result;
    }

    private static string BuildKey(Finding finding)
    {
        return string.Join(
            "|",
            finding.RuleId,
            finding.ServerName,
            finding.ToolName ?? string.Empty,
            finding.Evidence ?? string.Empty);
    }
}
