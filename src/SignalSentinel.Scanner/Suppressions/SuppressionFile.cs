// -----------------------------------------------------------------------
// <copyright file="SuppressionFile.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using System.Text.Json.Serialization;

namespace SignalSentinel.Scanner.Suppressions;

/// <summary>
/// Represents the on-disk schema of a <c>.sentinel-suppressions.json</c> file (schema v1.0).
/// Formally accepts risk on specific findings where compensating controls exist.
/// </summary>
public sealed record SuppressionFile
{
    /// <summary>
    /// File-schema version. Accepted values: "1.0".
    /// </summary>
    [JsonPropertyName("version")]
    public string Version { get; init; } = "1.0";

    /// <summary>
    /// Individual suppression entries.
    /// </summary>
    [JsonPropertyName("suppressions")]
    public IReadOnlyList<SuppressionEntry> Suppressions { get; init; } = [];
}

/// <summary>
/// One suppression entry in a <see cref="SuppressionFile"/>. All matching fields below
/// <see cref="RuleId"/> are optional; if present they must all match ordinally (AND
/// semantics, not OR) for the suppression to apply to a finding.
/// </summary>
public sealed record SuppressionEntry
{
    /// <summary>
    /// Rule identifier (e.g. "SS-014"). Required.
    /// </summary>
    [JsonPropertyName("ruleId")]
    public required string RuleId { get; init; }

    /// <summary>
    /// Optional MCP server name or skill name filter.
    /// </summary>
    [JsonPropertyName("serverName")]
    public string? ServerName { get; init; }

    /// <summary>
    /// Optional tool name filter.
    /// </summary>
    [JsonPropertyName("toolName")]
    public string? ToolName { get; init; }

    /// <summary>
    /// Optional skill name filter (synonym for <see cref="ServerName"/> when Source = Skill).
    /// </summary>
    [JsonPropertyName("skillName")]
    public string? SkillName { get; init; }

    /// <summary>
    /// Optional path filter (matches against the finding's skill file path).
    /// </summary>
    [JsonPropertyName("path")]
    public string? Path { get; init; }

    /// <summary>
    /// Optional line number filter (informational; not currently enforced by the matcher
    /// because v2.2 findings do not carry line numbers).
    /// </summary>
    [JsonPropertyName("line")]
    public int? Line { get; init; }

    /// <summary>
    /// Optional evidence-substring filter (ordinal substring match).
    /// </summary>
    [JsonPropertyName("evidence")]
    public string? Evidence { get; init; }

    /// <summary>
    /// Optional environment filter ("dev", "staging", "prod", etc.). Suppression applies
    /// only when <see cref="Config.ScanConfig.Environment"/> matches.
    /// </summary>
    [JsonPropertyName("environment")]
    public string? Environment { get; init; }

    /// <summary>
    /// Human-readable justification. Required.
    /// </summary>
    [JsonPropertyName("justification")]
    public required string Justification { get; init; }

    /// <summary>
    /// Identifier of the approver (email, GitHub handle, etc.).
    /// </summary>
    [JsonPropertyName("approvedBy")]
    public string? ApprovedBy { get; init; }

    /// <summary>
    /// Date the suppression was approved (ISO-8601).
    /// </summary>
    [JsonPropertyName("approvedOn")]
    public DateTimeOffset? ApprovedOn { get; init; }

    /// <summary>
    /// Date after which the suppression is no longer honoured (ISO-8601).
    /// </summary>
    [JsonPropertyName("expiresOn")]
    public DateTimeOffset? ExpiresOn { get; init; }
}
