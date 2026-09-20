// -----------------------------------------------------------------------
// <copyright file="DependencySurface.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.Osv;

/// <summary>Why an OSV lookup did or did not run for the discovered dependencies.</summary>
public enum DependencyQueryStatus
{
    /// <summary>--osv was not given; dependencies were recorded but not checked.</summary>
    NotRequested,

    /// <summary>Offline mode forbids the lookup (normally refused at argument parsing).</summary>
    Offline,

    /// <summary>The lookup ran; <see cref="DependencySurface.Vulnerabilities"/> is authoritative.</summary>
    Succeeded,

    /// <summary>The lookup was attempted but failed (network, timeout, bad response).</summary>
    Failed
}

/// <summary>
/// v3.0.0 (WP6): the dependency surface of the scanned skills plus the outcome of the
/// optional OSV vulnerability lookup. Carried on <c>ScanContext</c> so SS-039 and
/// SS-INFO-006 can reason about what was and was not checked.
/// </summary>
public sealed record DependencySurface
{
    /// <summary>All dependency references found, including unpinned ones never queried.</summary>
    public required IReadOnlyList<SkillDependency> Dependencies { get; init; }

    /// <summary>Whether the OSV lookup ran, was skipped, or failed.</summary>
    public required DependencyQueryStatus Status { get; init; }

    /// <summary>Operator-facing failure detail when <see cref="Status"/> is Failed.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Vulnerabilities returned by OSV for the queried packages.</summary>
    public IReadOnlyList<OsvVulnerability> Vulnerabilities { get; init; } = [];

    /// <summary>How many pinned packages were actually queried (capped at 100).</summary>
    public int QueriedCount { get; init; }

    /// <summary>True when more than 100 pinned packages were found and the rest were not queried.</summary>
    public bool Truncated { get; init; }
}
