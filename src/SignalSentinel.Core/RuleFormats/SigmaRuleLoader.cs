// -----------------------------------------------------------------------
// <copyright file="SigmaRuleLoader.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SignalSentinel.Core.RuleFormats;

/// <summary>
/// Loads a subset of the Sigma YAML detection rule format.
/// Supports <c>title</c>, <c>id</c>, <c>description</c>, <c>level</c>, <c>tags</c>,
/// <c>logsource</c>, and <c>detection.selection</c> with <c>contains</c> / <c>startswith</c> / <c>endswith</c> modifiers.
/// </summary>
/// <remarks>
/// Sigma correlation rules and backend-specific directives (e.g., Splunk SPL) are
/// intentionally out of scope for v2.2.0.
/// </remarks>
public static class SigmaRuleLoader
{
    private const int MaxRuleFileSizeBytes = 1 * 1024 * 1024;
    private const int MaxRulesPerLoad = 500;

    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    /// <summary>
    /// Loads all Sigma rules from a file or directory path.
    /// </summary>
    /// <param name="path">Absolute or relative path to a .yml/.yaml file or a directory containing such files.</param>
    /// <returns>Parsed Sigma rules. Invalid files are skipped and reported via <see cref="SigmaLoadResult.Errors"/>.</returns>
    public static SigmaLoadResult LoadFromPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var result = new SigmaLoadResult();

        if (File.Exists(path))
        {
            LoadFile(path, result);
        }
        else if (Directory.Exists(path))
        {
            var files = Directory.EnumerateFiles(path, "*.y*ml", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
                         || f.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
                .Take(MaxRulesPerLoad);

            foreach (var file in files)
            {
                LoadFile(file, result);
            }
        }
        else
        {
            result.Errors.Add($"Sigma path not found: {path}");
        }

        return result;
    }

    private static void LoadFile(string path, SigmaLoadResult result)
    {
        try
        {
            var info = new FileInfo(path);
            if (info.Length > MaxRuleFileSizeBytes)
            {
                result.Errors.Add($"Sigma rule file exceeds maximum size ({MaxRuleFileSizeBytes / 1024}KB): {Path.GetFileName(path)}");
                return;
            }

            var yaml = File.ReadAllText(path);
            var rule = Parse(yaml);
            if (rule is not null)
            {
                result.Rules.Add(rule);
            }
        }
        catch (YamlDotNet.Core.YamlException ex)
        {
            result.Errors.Add($"Malformed Sigma rule in {Path.GetFileName(path)}: {ex.Message}");
        }
        catch (IOException ex)
        {
            result.Errors.Add($"Could not read Sigma rule {Path.GetFileName(path)}: {ex.Message}");
        }
        catch (UnauthorizedAccessException)
        {
            result.Errors.Add($"Access denied reading Sigma rule: {Path.GetFileName(path)}");
        }
    }

    /// <summary>
    /// Parses a single Sigma YAML document. Returns null if the document cannot be mapped to a supported rule.
    /// </summary>
    /// <param name="yaml">Raw YAML document text.</param>
    /// <returns>Parsed rule or null.</returns>
    public static SigmaRule? Parse(string yaml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(yaml);

        var raw = Deserializer.Deserialize<SigmaRawDocument?>(yaml);
        if (raw is null || string.IsNullOrWhiteSpace(raw.Title))
        {
            return null;
        }

        if (raw.Detection is null)
        {
            return null;
        }

        var patterns = ExtractPatterns(raw.Detection);
        if (patterns.Count == 0)
        {
            return null;
        }

        return new SigmaRule
        {
            Title = raw.Title,
            Id = raw.Id ?? Guid.NewGuid().ToString(),
            Description = raw.Description ?? string.Empty,
            Level = MapLevel(raw.Level),
            Tags = raw.Tags ?? [],
            Product = raw.LogSource?.Product,
            Category = raw.LogSource?.Category,
            Patterns = patterns
        };
    }

    private static List<SigmaPattern> ExtractPatterns(Dictionary<string, object>? detection)
    {
        var patterns = new List<SigmaPattern>();
        if (detection is null)
        {
            return patterns;
        }

        foreach (var (selectionName, selectionValue) in detection)
        {
            // Skip the condition key - we implicitly OR all selections in v2.2.0
            if (string.Equals(selectionName, "condition", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (selectionValue is Dictionary<object, object> fields)
            {
                foreach (var (rawKey, rawValue) in fields)
                {
                    var keyText = rawKey?.ToString() ?? string.Empty;
                    var (field, matchType) = ParseField(keyText);
                    var values = NormaliseValues(rawValue);
                    foreach (var value in values)
                    {
                        patterns.Add(new SigmaPattern
                        {
                            SelectionName = selectionName,
                            FieldName = field,
                            MatchType = matchType,
                            Value = value
                        });
                    }
                }
            }
        }

        return patterns;
    }

    private static (string Field, SigmaMatchType Match) ParseField(string key)
    {
        // Sigma modifier syntax: field|contains, field|startswith, field|endswith
        var pipeIndex = key.IndexOf('|', StringComparison.Ordinal);
        if (pipeIndex < 0)
        {
            return (key, SigmaMatchType.Equals);
        }

        var field = key[..pipeIndex];
        var modifier = key[(pipeIndex + 1)..].ToLowerInvariant();
        var match = modifier switch
        {
            "contains" => SigmaMatchType.Contains,
            "startswith" => SigmaMatchType.StartsWith,
            "endswith" => SigmaMatchType.EndsWith,
            _ => SigmaMatchType.Equals
        };

        return (field, match);
    }

    private static List<string> NormaliseValues(object? raw)
    {
        var result = new List<string>();
        switch (raw)
        {
            case null:
                break;
            case string s:
                result.Add(s);
                break;
            case List<object> list:
                foreach (var item in list)
                {
                    var text = item?.ToString();
                    if (!string.IsNullOrEmpty(text))
                    {
                        result.Add(text);
                    }
                }
                break;
            default:
                var fallback = raw.ToString();
                if (!string.IsNullOrEmpty(fallback))
                {
                    result.Add(fallback);
                }
                break;
        }
        return result;
    }

    private static Severity MapLevel(string? level)
    {
        if (string.IsNullOrWhiteSpace(level))
        {
            return Severity.Medium;
        }

        return level.ToLowerInvariant() switch
        {
            "informational" or "info" => Severity.Info,
            "low" => Severity.Low,
            "medium" => Severity.Medium,
            "high" => Severity.High,
            "critical" => Severity.Critical,
            _ => Severity.Medium
        };
    }

    private sealed class SigmaRawDocument
    {
        public string? Title { get; set; }

        public string? Id { get; set; }

        public string? Description { get; set; }

        public string? Level { get; set; }

        public List<string>? Tags { get; set; }

        [YamlDotNet.Serialization.YamlMember(Alias = "logsource", ApplyNamingConventions = false)]
        public SigmaRawLogSource? LogSource { get; set; }

        public Dictionary<string, object>? Detection { get; set; }
    }

    private sealed class SigmaRawLogSource
    {
        public string? Product { get; set; }

        public string? Category { get; set; }
    }
}

/// <summary>
/// Result of loading one or more Sigma rules.
/// </summary>
public sealed class SigmaLoadResult
{
    /// <summary>
    /// Successfully parsed rules.
    /// </summary>
    public List<SigmaRule> Rules { get; } = [];

    /// <summary>
    /// Errors encountered during parsing (non-fatal; invalid files are skipped).
    /// </summary>
    public List<string> Errors { get; } = [];
}

/// <summary>
/// Parsed representation of a Sigma rule for MCP/Skill scanning.
/// </summary>
public sealed record SigmaRule
{
    /// <summary>
    /// Rule title.
    /// </summary>
    public required string Title { get; init; }

    /// <summary>
    /// Rule identifier (UUID).
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Rule description.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Severity mapped from Sigma <c>level</c>.
    /// </summary>
    public required Severity Level { get; init; }

    /// <summary>
    /// Sigma tags (e.g. <c>attack.credential_access</c>).
    /// </summary>
    public required IReadOnlyList<string> Tags { get; init; }

    /// <summary>
    /// Logsource product (e.g. <c>mcp</c>, <c>skill</c>).
    /// </summary>
    public string? Product { get; init; }

    /// <summary>
    /// Logsource category (e.g. <c>tool</c>, <c>instructions</c>).
    /// </summary>
    public string? Category { get; init; }

    /// <summary>
    /// Flattened pattern list parsed from <c>detection</c>.
    /// </summary>
    public required IReadOnlyList<SigmaPattern> Patterns { get; init; }
}

/// <summary>
/// A single pattern extracted from a Sigma detection selection.
/// </summary>
public sealed record SigmaPattern
{
    /// <summary>
    /// Selection group name (e.g. <c>selection</c>).
    /// </summary>
    public required string SelectionName { get; init; }

    /// <summary>
    /// Field the pattern applies to (e.g. <c>description</c>).
    /// </summary>
    public required string FieldName { get; init; }

    /// <summary>
    /// Match type derived from modifier (e.g. <c>|contains</c>).
    /// </summary>
    public required SigmaMatchType MatchType { get; init; }

    /// <summary>
    /// Literal value to match.
    /// </summary>
    public required string Value { get; init; }
}

/// <summary>
/// Sigma modifier match type.
/// </summary>
public enum SigmaMatchType
{
    /// <summary>
    /// Exact string equality.
    /// </summary>
    Equals,

    /// <summary>
    /// Substring match (<c>|contains</c>).
    /// </summary>
    Contains,

    /// <summary>
    /// Prefix match (<c>|startswith</c>).
    /// </summary>
    StartsWith,

    /// <summary>
    /// Suffix match (<c>|endswith</c>).
    /// </summary>
    EndsWith
}
