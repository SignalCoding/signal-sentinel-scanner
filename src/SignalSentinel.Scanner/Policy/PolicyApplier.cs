// -----------------------------------------------------------------------
// <copyright file="PolicyApplier.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Policy;

/// <summary>
/// v3.0.0 (WP7): applies a <see cref="ResolvedPolicy"/> to a deduplicated finding list.
/// Disabled rules are dropped; absolute severity overrides are applied next; findings
/// with no absolute override are raised one band when their rule is in the policy's
/// bump list or the policy bumps everything. Runs after dedup, before the confidence
/// filter.
/// </summary>
public static class PolicyApplier
{
    public static IReadOnlyList<Finding> Apply(IReadOnlyList<Finding> findings, ResolvedPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(policy);

        if (policy.IsEmpty)
        {
            return findings;
        }

        var result = new List<Finding>(findings.Count);
        foreach (var finding in findings)
        {
            if (policy.DisabledRules.Contains(finding.RuleId))
            {
                continue;
            }

            if (policy.SeverityOverrides.TryGetValue(finding.RuleId, out var absolute))
            {
                result.Add(finding with { Severity = absolute });
                continue;
            }

            if (policy.BumpAllOneBand || policy.BumpOneBandRules.Contains(finding.RuleId))
            {
                result.Add(finding with { Severity = BumpOneBand(finding.Severity) });
                continue;
            }

            result.Add(finding);
        }

        return result;
    }

    /// <summary>Raises a severity by one band, capped at <see cref="Severity.Critical"/>.</summary>
    internal static Severity BumpOneBand(Severity severity) =>
        severity >= Severity.Critical ? Severity.Critical : severity + 1;
}
