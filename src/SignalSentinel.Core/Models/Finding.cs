// -----------------------------------------------------------------------
// <copyright file="Finding.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Core.Models;

/// <summary>
/// Represents a security finding from scanning an MCP server.
/// </summary>
public sealed record Finding
{
    /// <summary>
    /// Unique rule identifier (e.g., "SS-001").
    /// </summary>
    public required string RuleId { get; init; }

    /// <summary>
    /// OWASP Agentic AI Security code (e.g., "ASI01").
    /// </summary>
    public required string OwaspCode { get; init; }

    /// <summary>
    /// Severity of the finding.
    /// </summary>
    public required Severity Severity { get; init; }

    /// <summary>
    /// Short title describing the finding.
    /// </summary>
    public required string Title { get; init; }

    /// <summary>
    /// Detailed description of the security issue.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Recommended remediation steps.
    /// </summary>
    public required string Remediation { get; init; }

    /// <summary>
    /// Name of the MCP server where the finding was discovered.
    /// </summary>
    public required string ServerName { get; init; }

    /// <summary>
    /// Name of the specific tool (if applicable).
    /// </summary>
    public string? ToolName { get; init; }

    /// <summary>
    /// Matched pattern or evidence (for transparency).
    /// </summary>
    public string? Evidence { get; init; }

    /// <summary>
    /// Confidence score (0.0 to 1.0) for pattern-based detections.
    /// </summary>
    public double? Confidence { get; init; }

    /// <summary>
    /// OWASP MCP Top 10 code (e.g., "MCP01") for dual mapping.
    /// Null for skill-only findings that have no MCP protocol mapping.
    /// </summary>
    public string? McpCode { get; init; }

    /// <summary>
    /// Source type indicating whether the finding originated from MCP or Skill scanning.
    /// </summary>
    public FindingSource Source { get; init; } = FindingSource.Mcp;

    /// <summary>
    /// Skill file path (for skill-originated findings).
    /// </summary>
    public string? SkillFilePath { get; init; }
}

/// <summary>
/// Source type for a finding.
/// </summary>
public enum FindingSource
{
    Mcp,
    Skill
}

/// <summary>
/// Represents an attack path across multiple MCP servers.
/// </summary>
public sealed record AttackPath
{
    /// <summary>
    /// Unique identifier for this attack path.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Description of the attack chain.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Severity of the attack path.
    /// </summary>
    public required Severity Severity { get; init; }

    /// <summary>
    /// OWASP codes covered by this attack path.
    /// </summary>
    public required IReadOnlyList<string> OwaspCodes { get; init; }

    /// <summary>
    /// Steps in the attack chain.
    /// </summary>
    public required IReadOnlyList<AttackPathStep> Steps { get; init; }

    /// <summary>
    /// Remediation guidance for the entire path.
    /// </summary>
    public required string Remediation { get; init; }
}

/// <summary>
/// Represents a single step in an attack path.
/// </summary>
public sealed record AttackPathStep
{
    /// <summary>
    /// Server name.
    /// </summary>
    public required string ServerName { get; init; }

    /// <summary>
    /// Tool name.
    /// </summary>
    public required string ToolName { get; init; }

    /// <summary>
    /// Capability exploited at this step.
    /// </summary>
    public required ToolCapability Capability { get; init; }

    /// <summary>
    /// Description of what happens at this step.
    /// </summary>
    public required string Description { get; init; }
}

/// <summary>
/// Tool capability classifications for attack path analysis.
/// </summary>
[Flags]
public enum ToolCapability
{
    None = 0,
    ReadFile = 1 << 0,
    WriteFile = 1 << 1,
    ReadData = 1 << 2,
    WriteData = 1 << 3,
    NetworkAccess = 1 << 4,
    CodeExecution = 1 << 5,
    MemoryWrite = 1 << 6,
    SystemAccess = 1 << 7,
    CredentialAccess = 1 << 8
}
