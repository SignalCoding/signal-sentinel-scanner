// -----------------------------------------------------------------------
// <copyright file="SentinelScopeFile.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json.Serialization;

namespace SignalSentinel.Scanner.Scope;

/// <summary>
/// On-disk schema (v1.0) of <c>.sentinel-scope.json</c>. Tells the scanner which
/// skills and servers are actually enabled at the target orchestrator, so the
/// scan grade reflects real attack surface and not dormant artefacts on disk.
/// v2.4.0 (G7).
/// </summary>
/// <remarks>
/// <para>
/// Scope is deliberately decoupled from any specific orchestrator. Any
/// orchestrator, CI pipeline, or human can produce this file - the scanner
/// does not parse orchestrator-native configuration of any vendor.
/// </para>
/// <para>
/// The scanner still enumerates every skill / server it can find. Findings
/// against out-of-scope targets are tagged <c>Scope = "dormant"</c>, retained
/// in reports for audit trail, and demoted to <see cref="Core.Models.Severity.Info"/>
/// by the grading algorithm so the surfaced grade reflects real posture.
/// </para>
/// </remarks>
public sealed record SentinelScopeFile
{
    /// <summary>File-schema version. Accepted: "1.0".</summary>
    [JsonPropertyName("version")]
    public string Version { get; init; } = "1.0";

    /// <summary>
    /// Free-text provenance label shown in the Scope Disclosure block of every
    /// report. Typically the name of the orchestrator that generated the file
    /// (e.g. <c>"my-orchestrator"</c>, <c>"agent-runtime"</c>, <c>"manual"</c>,
    /// <c>"ci"</c>). Informational only; not consumed by the matcher.
    /// </summary>
    [JsonPropertyName("source")]
    public string? Source { get; init; }

    /// <summary>Skill scope (include / exclude lists).</summary>
    [JsonPropertyName("skills")]
    public ScopeSelector? Skills { get; init; }

    /// <summary>MCP server scope (include / exclude lists).</summary>
    [JsonPropertyName("servers")]
    public ScopeSelector? Servers { get; init; }
}

/// <summary>
/// A simple include/exclude pair. When <see cref="Include"/> is non-empty, only
/// listed names are in scope. When <see cref="Exclude"/> is non-empty, listed
/// names are explicitly out of scope. Both may be combined; include wins.
/// </summary>
public sealed record ScopeSelector
{
    /// <summary>Names that are in scope. Empty/null means "no include filter".</summary>
    [JsonPropertyName("include")]
    public IReadOnlyList<string>? Include { get; init; }

    /// <summary>Names that are explicitly out of scope.</summary>
    [JsonPropertyName("exclude")]
    public IReadOnlyList<string>? Exclude { get; init; }
}
