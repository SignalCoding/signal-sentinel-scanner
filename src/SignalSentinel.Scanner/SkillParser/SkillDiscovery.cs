// -----------------------------------------------------------------------
// <copyright file="SkillDiscovery.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.SkillParser;

/// <summary>
/// Auto-discovers Agent Skill directories for well-known platforms.
/// Security hardened with path validation and symlink protection.
/// </summary>
public static class SkillDiscovery
{
    /// <summary>
    /// Well-known platform skill directories.
    /// </summary>
    private static readonly (string Platform, string SubPath, bool IsProject)[] KnownPaths =
    [
        ("Claude Code", ".claude/skills", false),
        ("OpenAI Codex CLI", ".codex/skills", false),
        ("Cursor", ".cursor/skills", false),
        ("Windsurf", ".windsurf/skills", false),
        ("Generic Agent Skills", ".agent-skills", false),
    ];

    internal static readonly (string Platform, string SubPath)[] ProjectPaths =
    [
        ("Claude Code", ".claude/skills"),
        ("OpenAI Codex CLI", ".codex/skills"),
        ("Cursor", ".cursor/skills"),
        ("Windsurf", ".windsurf/skills"),
        ("Generic Agent Skills", ".agent-skills"),
        ("Gemini CLI", ".gemini/skills"),
        ("OpenCode", ".opencode/skills"),
        ("GitHub", ".github/skills"),
        ("Factory", ".factory/skills"),
        ("Generic Agents", ".agents/skills"),
    ];

    /// <summary>
    /// v3.0.0 (WP8): skills bundled inside Claude Code plugins live under the plugin
    /// cache (~/.claude/plugins/cache/&lt;owner&gt;/&lt;plugin&gt;/skills) and marketplace checkouts
    /// (~/.claude/plugins/marketplaces/.../skills at any depth). Both are enumerated with
    /// hard bounds; anything unreadable is skipped.
    /// </summary>
    internal static IReadOnlyList<string> PluginCacheSkillDirectories(string homeDir)
    {
        const int maxDirectories = 100;
        var results = new List<string>();

        if (string.IsNullOrEmpty(homeDir))
        {
            return results;
        }

        var pluginsRoot = Path.Combine(homeDir, ".claude", "plugins");

        // cache/<owner>/<plugin>/skills — exactly two levels below "cache". Junctions
        // and symlinks are skipped so enumeration cannot escape the plugins root.
        var shallowOptions = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        var cacheRoot = Path.Combine(pluginsRoot, "cache");
        if (Directory.Exists(cacheRoot))
        {
            try
            {
                foreach (var owner in Directory.EnumerateDirectories(cacheRoot, "*", shallowOptions))
                {
                    foreach (var plugin in Directory.EnumerateDirectories(owner, "*", shallowOptions))
                    {
                        foreach (var skills in Directory.EnumerateDirectories(plugin, "skills", shallowOptions))
                        {
                            results.Add(skills);
                            if (results.Count >= maxDirectories)
                            {
                                return results;
                            }
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Partial results are fine; unreadable entries are skipped.
            }
        }

        // marketplaces/**/skills — any depth, bounded.
        var marketplacesRoot = Path.Combine(pluginsRoot, "marketplaces");
        if (Directory.Exists(marketplacesRoot))
        {
            try
            {
                var options = new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = 8,
                    AttributesToSkip = FileAttributes.ReparsePoint
                };
                foreach (var dir in Directory.EnumerateDirectories(marketplacesRoot, "skills", options))
                {
                    results.Add(dir);
                    if (results.Count >= maxDirectories)
                    {
                        return results;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Partial results are fine; unreadable entries are skipped.
            }
        }

        return results;
    }

    /// <summary>
    /// Discovers all skill directories from well-known platform locations.
    /// </summary>
    public static async Task<IReadOnlyList<SkillScanSource>> DiscoverAllAsync(
        bool verbose = false,
        Action<string>? logger = null,
        CancellationToken cancellationToken = default)
    {
        var sources = new List<SkillScanSource>();
        var homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (string.IsNullOrEmpty(homeDir))
        {
            return sources;
        }

        // Personal (global) skill directories
        foreach (var (platform, subPath, _) in KnownPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = Path.Combine(homeDir, subPath);
            if (!Directory.Exists(fullPath))
            {
                continue;
            }

            if (verbose)
            {
                logger?.Invoke($"Discovering skills: {platform} ({fullPath})");
            }

            var skills = await SkillReader.ReadDirectoryAsync(
                fullPath, platform, isProjectLevel: false, cancellationToken);

            if (skills.Count > 0)
            {
                sources.Add(new SkillScanSource
                {
                    SourcePath = fullPath,
                    Platform = platform,
                    Skills = skills
                });

                if (verbose)
                {
                    logger?.Invoke($"  Found {skills.Count} skill(s)");
                }
            }
        }

        // v3.0.0 (WP8): Claude Code plugin cache / marketplace skill directories.
        foreach (var cacheDir in PluginCacheSkillDirectories(homeDir))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (verbose)
            {
                logger?.Invoke($"Discovering skills: Claude Code (plugin cache) ({cacheDir})");
            }

            var skills = await SkillReader.ReadDirectoryAsync(
                cacheDir, "Claude Code (plugin cache)", isProjectLevel: false, cancellationToken);

            if (skills.Count > 0)
            {
                sources.Add(new SkillScanSource
                {
                    SourcePath = cacheDir,
                    Platform = "Claude Code (plugin cache)",
                    Skills = skills
                });
            }
        }

        // Project-level skill directories (current working directory)
        var cwd = Directory.GetCurrentDirectory();
        foreach (var (platform, subPath) in ProjectPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = Path.Combine(cwd, subPath);
            if (!Directory.Exists(fullPath))
            {
                continue;
            }

            if (verbose)
            {
                logger?.Invoke($"Discovering project skills: {platform} ({fullPath})");
            }

            var skills = await SkillReader.ReadDirectoryAsync(
                fullPath, platform, isProjectLevel: true, cancellationToken);

            if (skills.Count > 0)
            {
                sources.Add(new SkillScanSource
                {
                    SourcePath = fullPath,
                    Platform = $"{platform} (project)",
                    Skills = skills
                });
            }
        }

        return sources;
    }

    /// <summary>
    /// Scans a specific directory for skill files.
    /// </summary>
    public static async Task<SkillScanSource> ScanDirectoryAsync(
        string directory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(directory);

        var fullPath = Path.GetFullPath(directory);
        var errors = new List<string>();

        if (!Directory.Exists(fullPath))
        {
            // It might be a single SKILL.md file
            if (File.Exists(fullPath) &&
                Path.GetFileName(fullPath).Equals("SKILL.md", StringComparison.OrdinalIgnoreCase))
            {
                var skill = await SkillReader.ReadAsync(fullPath, cancellationToken: cancellationToken);
                return new SkillScanSource
                {
                    SourcePath = fullPath,
                    Skills = skill is not null ? [skill] : [],
                    Errors = errors
                };
            }

            errors.Add($"Directory not found: {Path.GetFileName(fullPath)}");
            return new SkillScanSource
            {
                SourcePath = fullPath,
                Skills = [],
                Errors = errors
            };
        }

        var skills = await SkillReader.ReadDirectoryAsync(
            fullPath, cancellationToken: cancellationToken);

        return new SkillScanSource
        {
            SourcePath = fullPath,
            Skills = skills,
            Errors = errors
        };
    }
}
