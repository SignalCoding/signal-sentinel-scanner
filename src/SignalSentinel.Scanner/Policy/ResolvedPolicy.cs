// -----------------------------------------------------------------------
// <copyright file="ResolvedPolicy.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Policy;

/// <summary>
/// v3.0.0 (WP7): a resolved <c>--policy</c> preset or JSON file. Produced by
/// <see cref="PolicyLoader"/>, applied to findings by <see cref="PolicyApplier"/>, and
/// folded into <c>ScanConfig</c> (fail-on, min-confidence, offline) by the CLI host.
/// Explicit CLI flags always win over anything the policy sets.
/// </summary>
public sealed record ResolvedPolicy
{
    /// <summary>Preset name ("default", "strict", "defence") or the source file path.</summary>
    public required string Name { get; init; }

    /// <summary>Absolute severity overrides by rule ID (case-insensitive). Win over band bumps.</summary>
    public IReadOnlyDictionary<string, Severity> SeverityOverrides { get; init; } =
        new Dictionary<string, Severity>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Rule IDs whose findings are raised one severity band (the strict preset).</summary>
    public IReadOnlySet<string> BumpOneBandRules { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>When true, every finding is raised one severity band (the defence preset).</summary>
    public bool BumpAllOneBand { get; init; }

    /// <summary>Rule IDs whose findings are dropped entirely.</summary>
    public IReadOnlySet<string> DisabledRules { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Fail-on threshold supplied by the policy; used only when --fail-on was not given.</summary>
    public Severity? FailOn { get; init; }

    /// <summary>Minimum confidence supplied by the policy; used only when --min-confidence was not given.</summary>
    public double? MinConfidence { get; init; }

    /// <summary>When true, the policy implies offline operation (the defence preset).</summary>
    public bool ImpliesOffline { get; init; }

    /// <summary>An empty policy that changes nothing (the "default" preset).</summary>
    public static ResolvedPolicy Default { get; } = new() { Name = "default" };

    /// <summary>True when the policy neither drops, re-severities, nor re-thresholds anything.</summary>
    public bool IsEmpty =>
        SeverityOverrides.Count == 0
        && BumpOneBandRules.Count == 0
        && !BumpAllOneBand
        && DisabledRules.Count == 0
        && FailOn is null
        && MinConfidence is null
        && !ImpliesOffline;
}
