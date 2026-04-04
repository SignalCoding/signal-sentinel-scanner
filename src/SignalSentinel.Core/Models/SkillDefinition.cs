// -----------------------------------------------------------------------
// <copyright file="SkillDefinition.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Core.Models;

/// <summary>
/// Represents a parsed Agent Skill (SKILL.md format).
/// </summary>
public sealed record SkillDefinition
{
    /// <summary>
    /// Skill name from YAML frontmatter.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Skill description from YAML frontmatter.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// Context setting from frontmatter (e.g., "full", "fork", "none").
    /// </summary>
    public string? Context { get; init; }

    /// <summary>
    /// Agent override from frontmatter.
    /// </summary>
    public string? Agent { get; init; }

    /// <summary>
    /// Raw YAML frontmatter content.
    /// </summary>
    public string? RawFrontmatter { get; init; }

    /// <summary>
    /// Markdown body (instructions) after frontmatter.
    /// </summary>
    public required string InstructionsBody { get; init; }

    /// <summary>
    /// Full raw content of the SKILL.md file.
    /// </summary>
    public required string RawContent { get; init; }

    /// <summary>
    /// File path to the SKILL.md file.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Source platform (e.g., "Claude Code", "Cursor", "Codex CLI").
    /// </summary>
    public string? SourcePlatform { get; init; }

    /// <summary>
    /// Whether this is a project-level skill (vs personal/global).
    /// </summary>
    public bool IsProjectLevel { get; init; }

    /// <summary>
    /// Bundled scripts found in the skill package.
    /// </summary>
    public IReadOnlyList<BundledScript> Scripts { get; init; } = [];

    /// <summary>
    /// Additional files found in the skill package directory.
    /// </summary>
    public IReadOnlyList<string> AdditionalFiles { get; init; } = [];

    /// <summary>
    /// All additional frontmatter keys not explicitly modelled.
    /// </summary>
    public IReadOnlyDictionary<string, string> ExtraFrontmatter { get; init; } =
        new Dictionary<string, string>();
}

/// <summary>
/// Represents a bundled script file within a skill package.
/// </summary>
public sealed record BundledScript
{
    /// <summary>
    /// File path relative to the skill directory.
    /// </summary>
    public required string RelativePath { get; init; }

    /// <summary>
    /// Absolute file path.
    /// </summary>
    public required string FullPath { get; init; }

    /// <summary>
    /// Script language based on file extension.
    /// </summary>
    public required ScriptLanguage Language { get; init; }

    /// <summary>
    /// Script content (loaded on demand, may be null for very large files).
    /// </summary>
    public string? Content { get; init; }

    /// <summary>
    /// File size in bytes.
    /// </summary>
    public long FileSize { get; init; }
}

/// <summary>
/// Script language classification.
/// </summary>
public enum ScriptLanguage
{
    Unknown,
    Python,
    Bash,
    PowerShell,
    JavaScript,
    TypeScript
}

/// <summary>
/// Result of scanning skills from a directory or package.
/// </summary>
public sealed record SkillScanSource
{
    /// <summary>
    /// Directory or package path that was scanned.
    /// </summary>
    public required string SourcePath { get; init; }

    /// <summary>
    /// Platform this skill source belongs to.
    /// </summary>
    public string? Platform { get; init; }

    /// <summary>
    /// Skills found at this source.
    /// </summary>
    public required IReadOnlyList<SkillDefinition> Skills { get; init; }

    /// <summary>
    /// Errors encountered during parsing.
    /// </summary>
    public IReadOnlyList<string> Errors { get; init; } = [];
}
