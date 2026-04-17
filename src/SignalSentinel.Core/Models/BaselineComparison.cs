// -----------------------------------------------------------------------
// <copyright file="BaselineComparison.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Core.Models;

/// <summary>
/// Result of comparing a current scan against a stored baseline.
/// Used by SS-022 (Rug Pull Detection) to identify tool schema mutations.
/// </summary>
public sealed record BaselineComparison
{
    /// <summary>
    /// Whether a baseline file was found and successfully loaded.
    /// </summary>
    public required bool BaselineLoaded { get; init; }

    /// <summary>
    /// Scanner version that produced the baseline (if loaded).
    /// </summary>
    public string? BaselineScannerVersion { get; init; }

    /// <summary>
    /// Timestamp when the baseline was created (if loaded).
    /// </summary>
    public DateTimeOffset? BaselineGeneratedAt { get; init; }

    /// <summary>
    /// Tools that have changed (description or parameters mutated) since baseline.
    /// </summary>
    public IReadOnlyList<SchemaMutation> MutatedTools { get; init; } = [];

    /// <summary>
    /// Tools that appear in the current scan but were not in the baseline.
    /// </summary>
    public IReadOnlyList<ToolIdentity> AddedTools { get; init; } = [];

    /// <summary>
    /// Tools that were in the baseline but are missing from the current scan.
    /// </summary>
    public IReadOnlyList<ToolIdentity> RemovedTools { get; init; } = [];

    /// <summary>
    /// True if any mutations, additions, or removals are detected.
    /// </summary>
    public bool HasChanges =>
        MutatedTools.Count > 0 || AddedTools.Count > 0 || RemovedTools.Count > 0;
}

/// <summary>
/// Identifies a tool uniquely by server + tool name.
/// </summary>
public sealed record ToolIdentity
{
    /// <summary>
    /// Server name hosting the tool.
    /// </summary>
    public required string ServerName { get; init; }

    /// <summary>
    /// Tool name.
    /// </summary>
    public required string ToolName { get; init; }
}

/// <summary>
/// Represents a detected schema mutation for a tool that existed in baseline and current scan.
/// </summary>
public sealed record SchemaMutation
{
    /// <summary>
    /// Identity of the mutated tool.
    /// </summary>
    public required ToolIdentity Tool { get; init; }

    /// <summary>
    /// Type of mutation detected.
    /// </summary>
    public required MutationType Type { get; init; }

    /// <summary>
    /// Hash of the tool from the baseline.
    /// </summary>
    public required string BaselineHash { get; init; }

    /// <summary>
    /// Hash of the tool from the current scan.
    /// </summary>
    public required string CurrentHash { get; init; }

    /// <summary>
    /// Short human-readable summary of what changed.
    /// </summary>
    public required string Summary { get; init; }
}

/// <summary>
/// Type of schema mutation.
/// </summary>
public enum MutationType
{
    /// <summary>
    /// Tool description text changed.
    /// </summary>
    DescriptionChanged,

    /// <summary>
    /// Tool parameter schema changed (added, removed, or type-changed parameters).
    /// </summary>
    ParametersChanged,

    /// <summary>
    /// Both description and parameters changed.
    /// </summary>
    BothChanged
}
