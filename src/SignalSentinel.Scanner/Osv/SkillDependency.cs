// -----------------------------------------------------------------------
// <copyright file="SkillDependency.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.Osv;

/// <summary>
/// v3.0.0 (WP6): a package dependency reference found in a skill — in its instructions
/// (<c>pip install a==1.2</c>, <c>npm install a@1.2</c>) or in a bundled manifest
/// (requirements.txt, package.json, pyproject.toml).
/// </summary>
public sealed record SkillDependency
{
    /// <summary>Package name, lower-cased (PyPI and npm names are case-insensitive).</summary>
    public required string Name { get; init; }

    /// <summary>Exact pinned version, or null when the reference is unpinned/ranged.</summary>
    public string? Version { get; init; }

    /// <summary>OSV ecosystem name: "PyPI" or "npm".</summary>
    public required string Ecosystem { get; init; }

    /// <summary>Where the reference was found (e.g. "instructions", "requirements.txt").</summary>
    public required string Source { get; init; }

    /// <summary>Name of the skill that carries the reference.</summary>
    public required string SkillName { get; init; }
}
