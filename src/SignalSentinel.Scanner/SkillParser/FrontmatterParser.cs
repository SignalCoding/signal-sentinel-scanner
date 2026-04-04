// -----------------------------------------------------------------------
// <copyright file="FrontmatterParser.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;

namespace SignalSentinel.Scanner.SkillParser;

/// <summary>
/// Parses YAML frontmatter from SKILL.md files.
/// Uses lightweight regex parsing to avoid external YAML library dependency.
/// Security hardened with input size limits and regex timeouts.
/// </summary>
public static partial class FrontmatterParser
{
    private const int MaxFrontmatterLength = 50_000;

    [GeneratedRegex(
        @"^---\s*\n(.*?)\n---\s*\n",
        RegexOptions.Singleline | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex FrontmatterBlock();

    [GeneratedRegex(
        @"^([a-zA-Z_][a-zA-Z0-9_-]*)\s*:\s*(.*)$",
        RegexOptions.Multiline | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex YamlKeyValue();

    /// <summary>
    /// Parses a SKILL.md file into frontmatter key-value pairs and the remaining markdown body.
    /// </summary>
    public static FrontmatterResult Parse(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        if (content.Length > MaxFrontmatterLength * 10)
        {
            content = content[..(MaxFrontmatterLength * 10)];
        }

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string body;
        string? rawFrontmatter = null;

        try
        {
            var match = FrontmatterBlock().Match(content);
            if (match.Success)
            {
                rawFrontmatter = match.Groups[1].Value;

                if (rawFrontmatter.Length <= MaxFrontmatterLength)
                {
                    foreach (Match kvMatch in YamlKeyValue().Matches(rawFrontmatter))
                    {
                        var key = kvMatch.Groups[1].Value.Trim();
                        var value = kvMatch.Groups[2].Value.Trim().Trim('"', '\'');

                        if (key.Length <= 100 && value.Length <= 10_000)
                        {
                            fields[key] = value;
                        }

                        if (fields.Count > 50)
                        {
                            break;
                        }
                    }
                }

                body = content[(match.Index + match.Length)..];
            }
            else
            {
                body = content;
            }
        }
        catch (RegexMatchTimeoutException)
        {
            body = content;
        }

        return new FrontmatterResult
        {
            Fields = fields,
            Body = body,
            RawFrontmatter = rawFrontmatter,
            HasFrontmatter = rawFrontmatter is not null
        };
    }
}

/// <summary>
/// Result of parsing YAML frontmatter from a SKILL.md file.
/// </summary>
public sealed record FrontmatterResult
{
    public required IReadOnlyDictionary<string, string> Fields { get; init; }
    public required string Body { get; init; }
    public string? RawFrontmatter { get; init; }
    public bool HasFrontmatter { get; init; }

    public string? GetField(string key) =>
        Fields.TryGetValue(key, out var value) ? value : null;
}
