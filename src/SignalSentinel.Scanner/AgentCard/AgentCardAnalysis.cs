// -----------------------------------------------------------------------
// <copyright file="AgentCardAnalysis.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.AgentCard;

/// <summary>How an <c>--agent-card</c> target was obtained.</summary>
public enum AgentCardStatus
{
    /// <summary>The card was read and parsed.</summary>
    Loaded,

    /// <summary>The card could not be fetched, read, or parsed; see <see cref="AgentCardAnalysis.FailureReason"/>.</summary>
    Failed
}

/// <summary>
/// v3.0.0 (WP9): the parsed subset of an A2A Agent Card that SS-042 evaluates, plus where
/// it came from. Only the fields the rule needs are retained; the raw document is not kept.
/// </summary>
public sealed record AgentCardAnalysis
{
    /// <summary>The URL or file path the operator supplied (after well-known expansion).</summary>
    public required string Source { get; init; }

    /// <summary>True when <see cref="Source"/> was fetched over the network.</summary>
    public bool FromNetwork { get; init; }

    /// <summary>Load outcome.</summary>
    public required AgentCardStatus Status { get; init; }

    /// <summary>Exception type name or short reason when <see cref="Status"/> is Failed.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Agent <c>name</c>, or the source host/file name when absent.</summary>
    public string DisplayName { get; init; } = string.Empty;

    /// <summary>Top-level <c>description</c>.</summary>
    public string? Description { get; init; }

    /// <summary>The agent's declared endpoint <c>url</c>.</summary>
    public string? EndpointUrl { get; init; }

    /// <summary>Declared skills (id/name plus description).</summary>
    public IReadOnlyList<AgentCardSkill> Skills { get; init; } = [];

    /// <summary>True when <c>securitySchemes</c> (or the legacy <c>authentication</c>) declares at least one scheme.</summary>
    public bool DeclaresSecurityScheme { get; init; }

    /// <summary>True when <c>securitySchemes</c> was present but empty (as opposed to absent).</summary>
    public bool SecuritySchemesEmpty { get; init; }
}

/// <summary>One entry of an Agent Card's <c>skills</c> array.</summary>
public sealed record AgentCardSkill(string Name, string? Description);
