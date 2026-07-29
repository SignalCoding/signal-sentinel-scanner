// -----------------------------------------------------------------------
// <copyright file="SkillDefinition.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Collections.Immutable;
using System.IO;

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
        ImmutableDictionary<string, string>.Empty;

    /// <summary>
    /// v2.3.0: capabilities declared in the <c>capabilities:</c> frontmatter
    /// key. Supports inline form (<c>capabilities: [read-filesystem, network]</c>)
    /// and block form (newline-separated <c>- read-filesystem</c> entries).
    /// When non-empty, SS-012 treats this list as authoritative and only fires
    /// on capabilities not declared here.
    /// </summary>
    public IReadOnlyList<string> Capabilities { get; init; } = [];

    /// <summary>
    /// v2.5.0 (G15b): filenames declared in a <c>deny_write</c> (or nested
    /// <c>permissions: deny_write:</c>) frontmatter key, per the OWASP Agentic
    /// Skills Top 10 "Universal Skill Format" proposal. A skill that explicitly
    /// commits to not writing a file is making a stronger claim than silence;
    /// the SS-028 rule (Skill Identity/Memory File Write Access) treats an
    /// instructions/script write to a file that's also listed here as a
    /// self-contradiction and escalates severity accordingly.
    /// </summary>
    public IReadOnlyList<string> DenyWrite { get; init; } = [];

    /// <summary>
    /// v2.4.1 (G11): stable skill identity used for suppression/scope matching.
    /// Normalised frontmatter <see cref="Name"/> (trimmed) when non-empty, else the
    /// name of the skill's containing directory. Distinct from <see cref="Name"/>
    /// itself so callers always have one unambiguous identity to key on even when
    /// <see cref="Name"/> was defaulted to "unnamed-skill" by the parser.
    /// </summary>
    public string CanonicalSkillName =>
        !string.IsNullOrWhiteSpace(Name)
            ? Name.Trim()
            : Path.GetFileName(Path.GetDirectoryName(FilePath)?.TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)) is { Length: > 0 } dirName
                ? dirName
                : Name;
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
