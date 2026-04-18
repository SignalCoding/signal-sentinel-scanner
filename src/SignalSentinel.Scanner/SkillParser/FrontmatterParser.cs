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

    /// <summary>
    /// v2.3.0: parses a list-valued frontmatter field. Supports both inline
    /// form (<c>key: [a, "b", c]</c>) and block form
    /// (<c>key:\n  - a\n  - b</c>). Returns an empty list if the field is
    /// absent or cannot be parsed. Items are stripped of quotes and
    /// whitespace; empty items are dropped.
    /// </summary>
    public IReadOnlyList<string> GetListField(string key)
    {
        // Block form first: scanning RawFrontmatter is authoritative because
        // the inline YAML KV regex can spill across newlines when the block
        // form is used.
        if (RawFrontmatter is not null)
        {
            var blockItems = ParseBlockList(RawFrontmatter, key);
            if (blockItems.Count > 0)
            {
                return blockItems;
            }
        }

        if (!Fields.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
        {
            return System.Array.Empty<string>();
        }

        // Inline form: [a, b, "c"]  (our KV regex already trimmed to 'a, b, "c"'
        // but may have retained the brackets - strip defensively).
        var trimmed = value.Trim().TrimStart('[').TrimEnd(']');
        var items = trimmed
            .Split(',', System.StringSplitOptions.RemoveEmptyEntries | System.StringSplitOptions.TrimEntries)
            .Select(s => s.Trim().Trim('"', '\''))
            .Where(s => s.Length > 0)
            .ToList();

        return items;
    }

    private static List<string> ParseBlockList(string frontmatter, string key)
    {
        var lines = frontmatter.Split('\n');
        var result = new List<string>();
        bool inBlock = false;

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');

            if (!inBlock)
            {
                var trimmedStart = line.TrimStart();
                if (trimmedStart.StartsWith(key + ":", System.StringComparison.OrdinalIgnoreCase)
                    && string.IsNullOrWhiteSpace(trimmedStart[(key.Length + 1)..]))
                {
                    inBlock = true;
                }
                continue;
            }

            if (line.Length > 0 && !char.IsWhiteSpace(line[0]))
            {
                // New top-level key - block ended.
                break;
            }

            var itemLine = line.TrimStart();
            if (!itemLine.StartsWith('-'))
            {
                if (string.IsNullOrWhiteSpace(itemLine))
                {
                    continue;
                }
                break;
            }

            var item = itemLine[1..].Trim().Trim('"', '\'');
            if (item.Length > 0)
            {
                result.Add(item);
            }

            if (result.Count > 64)
            {
                break;
            }
        }

        return result;
    }
}
