// -----------------------------------------------------------------------
// <copyright file="SkillReader.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.SkillParser;

/// <summary>
/// Reads and parses SKILL.md files into <see cref="SkillDefinition"/> records.
/// Security hardened with file size limits and safe path validation.
/// </summary>
public static class SkillReader
{
    private const long MaxSkillFileSize = 5 * 1024 * 1024; // 5 MB
    private const string SkillFileName = "SKILL.md";

    /// <summary>
    /// Reads a single SKILL.md file and returns a parsed SkillDefinition.
    /// </summary>
    public static async Task<SkillDefinition?> ReadAsync(
        string filePath,
        string? sourcePlatform = null,
        bool isProjectLevel = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        var fullPath = Path.GetFullPath(filePath);

        if (!File.Exists(fullPath))
        {
            return null;
        }

        var fileInfo = new FileInfo(fullPath);
        if (fileInfo.Length > MaxSkillFileSize)
        {
            return null;
        }

        string content;
        try
        {
            content = await File.ReadAllTextAsync(fullPath, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(content))
        {
            return null;
        }

        var parsed = FrontmatterParser.Parse(content);
        var skillDir = Path.GetDirectoryName(fullPath) ?? fullPath;
        var scripts = await ScriptInventory.DiscoverAsync(skillDir, cancellationToken);

        var name = parsed.GetField("name")
            ?? Path.GetFileName(Path.GetDirectoryName(fullPath))
            ?? "unnamed-skill";

        var extraFields = new Dictionary<string, string>();
        var knownKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "name", "description", "context", "agent"
        };

        foreach (var kvp in parsed.Fields)
        {
            if (!knownKeys.Contains(kvp.Key))
            {
                extraFields[kvp.Key] = kvp.Value;
            }
        }

        // Discover additional files in the skill directory
        var additionalFiles = new List<string>();
        try
        {
            foreach (var file in Directory.GetFiles(skillDir))
            {
                var fileName = Path.GetFileName(file);
                if (!fileName.Equals(SkillFileName, StringComparison.OrdinalIgnoreCase))
                {
                    additionalFiles.Add(fileName);
                }

                if (additionalFiles.Count > 100)
                {
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Silently skip if directory listing fails
        }

        return new SkillDefinition
        {
            Name = name,
            Description = parsed.GetField("description"),
            Context = parsed.GetField("context"),
            Agent = parsed.GetField("agent"),
            RawFrontmatter = parsed.RawFrontmatter,
            InstructionsBody = parsed.Body,
            RawContent = content,
            FilePath = fullPath,
            SourcePlatform = sourcePlatform,
            IsProjectLevel = isProjectLevel,
            Scripts = scripts,
            AdditionalFiles = additionalFiles,
            ExtraFrontmatter = extraFields
        };
    }

    /// <summary>
    /// Reads all SKILL.md files from a directory (recursively).
    /// </summary>
    public static async Task<IReadOnlyList<SkillDefinition>> ReadDirectoryAsync(
        string directory,
        string? sourcePlatform = null,
        bool isProjectLevel = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(directory);

        var fullDir = Path.GetFullPath(directory);
        if (!Directory.Exists(fullDir))
        {
            return [];
        }

        string[] skillFiles;
        try
        {
            skillFiles = Directory.GetFiles(fullDir, SkillFileName, SearchOption.AllDirectories);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }

        const int maxSkillsPerDirectory = 500;
        var skills = new List<SkillDefinition>();

        foreach (var file in skillFiles.Take(maxSkillsPerDirectory))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var skill = await ReadAsync(file, sourcePlatform, isProjectLevel, cancellationToken);
            if (skill is not null)
            {
                skills.Add(skill);
            }
        }

        return skills;
    }
}
