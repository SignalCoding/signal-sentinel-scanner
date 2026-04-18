// -----------------------------------------------------------------------
// <copyright file="ConfidenceFilter.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Triage;

/// <summary>
/// v2.3.0 confidence-aware triage. Applies <c>--min-confidence</c> filtering and
/// <c>--triage</c> demotion to a finding list.
/// </summary>
public static class ConfidenceFilter
{
    /// <summary>
    /// Threshold below which findings are demoted to <see cref="Severity.Low"/> when
    /// <c>--triage</c> mode is active.
    /// </summary>
    public const double TriageDemotionThreshold = 0.75;

    /// <summary>
    /// Filters and/or demotes findings by confidence. A finding with a null confidence
    /// is treated as 1.0 (assumed reliable) to match v2.2 behaviour.
    /// </summary>
    /// <param name="findings">Input findings.</param>
    /// <param name="minConfidence">Minimum confidence to keep a finding (0..1).</param>
    /// <param name="triage">When true, below-threshold findings are retained but demoted to Low.</param>
    public static IReadOnlyList<Finding> Apply(
        IReadOnlyList<Finding> findings,
        double minConfidence,
        bool triage)
    {
        ArgumentNullException.ThrowIfNull(findings);
        if (minConfidence is < 0 or > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(minConfidence), minConfidence, "Must be between 0 and 1 inclusive.");
        }

        if (minConfidence <= 0 && !triage)
        {
            return findings;
        }

        var result = new List<Finding>(findings.Count);
        foreach (var finding in findings)
        {
            var confidence = finding.Confidence ?? 1.0;

            if (confidence < minConfidence)
            {
                // Hard filter: drop.
                continue;
            }

            if (triage && confidence < TriageDemotionThreshold && finding.Severity > Severity.Low)
            {
                result.Add(finding with { Severity = Severity.Low });
                continue;
            }

            result.Add(finding);
        }
        return result;
    }
}
