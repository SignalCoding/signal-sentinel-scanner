// -----------------------------------------------------------------------
// <copyright file="ServerSourceAnalysis.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.ServerSource;

/// <summary>
/// v3.0.0 (WP9): the outcome of a <c>--server-source</c> walk. Sinks are only reported for
/// files that also register MCP tools, so the list is the co-location evidence SS-041 needs.
/// </summary>
public sealed record ServerSourceAnalysis
{
    /// <summary>Absolute root that was walked.</summary>
    public required string RootPath { get; init; }

    /// <summary>Display name for findings (the root directory's leaf name).</summary>
    public required string DisplayName { get; init; }

    /// <summary>Number of source files read.</summary>
    public int FilesScanned { get; init; }

    /// <summary>Number of files in which a tool registration was recognised.</summary>
    public int ToolFiles { get; init; }

    /// <summary>True when the file or directory cap stopped the walk early.</summary>
    public bool Truncated { get; init; }

    /// <summary>Dangerous sinks co-located with tool registrations.</summary>
    public IReadOnlyList<SourceSink> Sinks { get; init; } = [];
}

/// <summary>One dangerous call site in a file that registers MCP tools.</summary>
public sealed record SourceSink
{
    /// <summary>Path relative to <see cref="ServerSourceAnalysis.RootPath"/>, forward slashes.</summary>
    public required string RelativePath { get; init; }

    /// <summary>1-based line number.</summary>
    public required int Line { get; init; }

    /// <summary>Sink family, e.g. "child_process.exec", "eval", "subprocess shell=True".</summary>
    public required string Kind { get; init; }

    /// <summary>Why the family is dangerous.</summary>
    public required string Rationale { get; init; }

    /// <summary>Default severity for the family.</summary>
    public required Severity Severity { get; init; }

    /// <summary>The matched line, trimmed and bounded.</summary>
    public required string Snippet { get; init; }
}
