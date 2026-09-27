// -----------------------------------------------------------------------
// <copyright file="FrontmatterParser.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text;
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

    // v2.5.0 (G15): the key character class includes '.' so dotted flat-key
    // conventions like "network.allow: [...]" or "permissions.deny_write: [...]"
    // parse correctly. Prior to this fix, a dot in the key made the whole line fail
    // to match, so those fields were silently unparseable from real SKILL.md files
    // even though rule logic already checked for them via ExtraFrontmatter.
    [GeneratedRegex(
        @"^([a-zA-Z_][a-zA-Z0-9_.-]*)\s*:\s*(.*)$",
        RegexOptions.Multiline | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex YamlKeyValue();

    // v3.0.1 (F1): a YAML block-scalar header - "|" (literal) or ">" (folded), an
    // optional explicit indentation digit, and an optional chomping indicator
    // ("-" strip, "+" keep, absent = clip). Anything else is an ordinary value.
    [GeneratedRegex(
        @"^([|>])(\d?)([+-]?)$",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex BlockScalarHeader();

    /// <summary>Maximum characters accumulated for a single block scalar before the value is capped.</summary>
    private const int MaxBlockScalarLength = 20_000;

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
                    ParseFields(rawFrontmatter, fields);
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

    /// <summary>
    /// v3.1.0 (A1/C3): caps recursion when a nested block mapping is deeper than this,
    /// so hostile input cannot force unbounded descent. Real Universal Skill Format
    /// permission blocks are 2-3 levels deep.
    /// </summary>
    private const int MaxNestedMappingDepth = 10;

    /// <summary>
    /// v3.0.1 (F1): walks the frontmatter a line at a time so YAML block scalars
    /// (<c>key: &gt;</c>, <c>&gt;-</c>, <c>&gt;+</c>, <c>|</c>, <c>|-</c>, <c>|+</c>) collapse to their
    /// folded/literal value instead of parsing to the bare indicator character.
    /// Single-line, quoted, dotted and list-valued fields keep their previous
    /// behaviour: only lines whose key starts in column 0 become fields, and the
    /// 100-character key / 10,000-character value / 50-field caps still apply.
    /// v3.1.0 (A1/C3): a column-0 key with no inline value whose following lines are
    /// indented further and look like <c>key: value</c> siblings (not a <c>- item</c>
    /// list, which keeps its pre-existing handling via <see cref="FrontmatterResult.GetListField"/>)
    /// is now a nested block mapping. Its descendants are flattened into the same flat
    /// dotted-key convention the codebase already understands (e.g. <c>permissions:
    /// \n  shell: true</c> surfaces as <c>permissions.shell</c>), and - because SS-017's
    /// existing checks read the bare/short form (<c>network</c>, <c>network.allow</c>) -
    /// a second alias with a leading <c>permissions.</c> segment stripped is also set
    /// when present, so both conventions resolve to the same value.
    /// </summary>
    private static void ParseFields(string rawFrontmatter, Dictionary<string, string> fields)
    {
        var lines = rawFrontmatter.Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var kvMatch = YamlKeyValue().Match(lines[i].TrimEnd('\r'));
            if (!kvMatch.Success)
            {
                continue;
            }

            var key = kvMatch.Groups[1].Value.Trim();
            var rawValue = kvMatch.Groups[2].Value.Trim();

            var header = BlockScalarHeader().Match(rawValue);
            string value;
            if (header.Success)
            {
                value = ReadBlockScalar(lines, ref i, literal: rawValue[0] == '|', chomping: header.Groups[3].Value);
            }
            else if (rawValue.Length == 0 &&
                     TryGetNestedBlockStart(lines, i, 0, out var nestedStart, out var nestedIndent))
            {
                var index = nestedStart;
                ParseNestedMapping(lines, ref index, nestedIndent, key, fields, depth: 1);
                i = index - 1; // the for loop's i++ resumes exactly where the block ended
                value = string.Empty;
            }
            else
            {
                value = rawValue.Trim('"', '\'');
            }

            SetFlatField(fields, key, value);

            if (fields.Count > 50)
            {
                break;
            }
        }
    }

    /// <summary>
    /// v3.1.0 (A1/C3): flattens the children of a nested block mapping starting at
    /// <paramref name="index"/> (all lines indented exactly <paramref name="levelIndent"/>)
    /// into <paramref name="fields"/> under <paramref name="keyPrefix"/>-dotted keys.
    /// Stops (without consuming) at the first line indented less than
    /// <paramref name="levelIndent"/>, leaving <paramref name="index"/> there for the
    /// caller to resume from.
    /// </summary>
    private static void ParseNestedMapping(
        string[] lines,
        ref int index,
        int levelIndent,
        string keyPrefix,
        Dictionary<string, string> fields,
        int depth)
    {
        while (index < lines.Length)
        {
            if (fields.Count > 50)
            {
                return;
            }

            var line = lines[index].TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line))
            {
                index++;
                continue;
            }

            var indent = line.Length - line.TrimStart(' ').Length;
            if (indent < levelIndent)
            {
                return;
            }

            if (indent != levelIndent)
            {
                // Irregular indentation (e.g. a malformed line) - skip defensively
                // rather than misparse the block's shape.
                index++;
                continue;
            }

            var trimmed = line.TrimStart();
            if (trimmed.StartsWith('-'))
            {
                // A list item at this level belongs to a parent key already consumed
                // via TryGetNestedListStart/ReadFlatList; nothing to do here.
                index++;
                continue;
            }

            var kv = YamlKeyValue().Match(trimmed);
            if (!kv.Success)
            {
                index++;
                continue;
            }

            var key = kv.Groups[1].Value.Trim();
            var rawValue = kv.Groups[2].Value.Trim();
            var dottedKey = keyPrefix + "." + key;

            if (rawValue.Length == 0 && TryGetNestedListStart(lines, index, indent, out var listStart))
            {
                index = listStart;
                var items = ReadFlatList(lines, ref index, indent);
                SetFlatFieldWithAlias(fields, dottedKey, "[" + string.Join(", ", items) + "]");
                continue;
            }

            if (rawValue.Length == 0 &&
                depth < MaxNestedMappingDepth &&
                TryGetNestedBlockStart(lines, index, indent, out var nestedStart, out var nestedIndent))
            {
                index = nestedStart;
                ParseNestedMapping(lines, ref index, nestedIndent, dottedKey, fields, depth + 1);
                continue;
            }

            SetFlatFieldWithAlias(fields, dottedKey, rawValue.Trim('"', '\''));
            index++;
        }
    }

    /// <summary>
    /// True when the next non-blank line after <paramref name="currentIndex"/> is
    /// indented more than <paramref name="parentIndent"/> and looks like a
    /// <c>key: value</c> sibling rather than a <c>- item</c> list entry.
    /// </summary>
    private static bool TryGetNestedBlockStart(
        string[] lines, int currentIndex, int parentIndent, out int nestedStartIndex, out int nestedIndent)
    {
        nestedStartIndex = -1;
        nestedIndent = 0;

        var next = currentIndex + 1;
        while (next < lines.Length && string.IsNullOrWhiteSpace(lines[next]))
        {
            next++;
        }

        if (next >= lines.Length)
        {
            return false;
        }

        var line = lines[next].TrimEnd('\r');
        var indent = line.Length - line.TrimStart(' ').Length;
        var trimmed = line.TrimStart();

        if (indent <= parentIndent || trimmed.Length == 0 || trimmed[0] == '-' || !YamlKeyValue().IsMatch(trimmed))
        {
            return false;
        }

        nestedStartIndex = next;
        nestedIndent = indent;
        return true;
    }

    /// <summary>
    /// True when the next non-blank line after <paramref name="currentIndex"/> is
    /// indented more than <paramref name="parentIndent"/> and is a <c>- item</c> list entry.
    /// </summary>
    private static bool TryGetNestedListStart(
        string[] lines, int currentIndex, int parentIndent, out int listStartIndex)
    {
        listStartIndex = -1;

        var next = currentIndex + 1;
        while (next < lines.Length && string.IsNullOrWhiteSpace(lines[next]))
        {
            next++;
        }

        if (next >= lines.Length)
        {
            return false;
        }

        var line = lines[next].TrimEnd('\r');
        var indent = line.Length - line.TrimStart(' ').Length;
        var trimmed = line.TrimStart();

        if (indent <= parentIndent || !trimmed.StartsWith('-'))
        {
            return false;
        }

        listStartIndex = next;
        return true;
    }

    /// <summary>
    /// Reads consecutive <c>- item</c> lines at a single indentation level (the first
    /// item's), returning their trimmed, unquoted values. Stops (without consuming) at
    /// the first line indented at or below <paramref name="parentIndent"/>.
    /// </summary>
    private static List<string> ReadFlatList(string[] lines, ref int index, int parentIndent)
    {
        var items = new List<string>();
        var listIndent = -1;

        while (index < lines.Length)
        {
            var line = lines[index].TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line))
            {
                index++;
                continue;
            }

            var indent = line.Length - line.TrimStart(' ').Length;
            if (indent <= parentIndent)
            {
                break;
            }

            if (listIndent < 0)
            {
                listIndent = indent;
            }

            if (indent != listIndent)
            {
                break;
            }

            var trimmed = line.TrimStart();
            if (!trimmed.StartsWith('-'))
            {
                break;
            }

            var item = trimmed[1..].Trim().Trim('"', '\'');
            if (item.Length > 0 && items.Count <= 64)
            {
                items.Add(item);
            }

            index++;

            if (items.Count > 64)
            {
                break;
            }
        }

        return items;
    }

    private static void SetFlatField(Dictionary<string, string> fields, string key, string value)
    {
        if (fields.Count > 50)
        {
            return;
        }

        if (key.Length <= 100 && value.Length <= 10_000)
        {
            fields[key] = value;
        }
    }

    /// <summary>
    /// v3.1.0 (A1/C3): sets the fully dotted nested key, and - when its top-level
    /// ancestor is literally <c>permissions</c> (the Universal Skill Format's
    /// conventional grouping key) - also sets the alias with that leading segment
    /// stripped, so SS-017's existing bare/short-form reads (<c>network</c>,
    /// <c>network.allow</c>, <c>shell</c>) resolve against the nested form too.
    /// </summary>
    private static void SetFlatFieldWithAlias(Dictionary<string, string> fields, string dottedKey, string value)
    {
        SetFlatField(fields, dottedKey, value);

        const string prefix = "permissions.";
        if (dottedKey.Length > prefix.Length && dottedKey.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            SetFlatField(fields, dottedKey[prefix.Length..], value);
        }
    }

    /// <summary>
    /// Reads the continuation lines of a block scalar whose header is at
    /// <paramref name="index"/>. Continuation lines are indented by at least one
    /// space; the block ends at the first non-blank line in column 0.
    /// <paramref name="index"/> is advanced to the last line consumed.
    /// </summary>
    private static string ReadBlockScalar(string[] lines, ref int index, bool literal, string chomping)
    {
        var content = new List<string>();
        var baseIndent = -1;
        var accumulated = 0;

        var next = index + 1;
        for (; next < lines.Length; next++)
        {
            var line = lines[next].TrimEnd('\r');

            if (string.IsNullOrWhiteSpace(line))
            {
                if (accumulated <= MaxBlockScalarLength)
                {
                    content.Add(string.Empty);
                }

                continue;
            }

            if (!char.IsWhiteSpace(line[0]))
            {
                // A non-blank line in column 0 starts the next field: the block ends here.
                break;
            }

            if (baseIndent < 0)
            {
                baseIndent = line.Length - line.TrimStart(' ', '\t').Length;
            }

            var stripped = line.Length >= baseIndent ? line[baseIndent..] : line.TrimStart(' ', '\t');
            accumulated += stripped.Length + 1;
            if (accumulated <= MaxBlockScalarLength)
            {
                content.Add(stripped);
            }
        }

        index = next - 1;

        var trailingBlankLines = 0;
        while (content.Count > 0 && content[^1].Length == 0)
        {
            content.RemoveAt(content.Count - 1);
            trailingBlankLines++;
        }

        if (content.Count == 0)
        {
            return string.Empty;
        }

        var body = literal ? string.Join('\n', content) : Fold(content);

        return chomping switch
        {
            "-" => body,
            "+" => body + new string('\n', trailingBlankLines + 1),
            _ => body + "\n"
        };
    }

    /// <summary>
    /// YAML 1.2 folding: consecutive non-empty lines join with a single space, and a
    /// run of N blank lines between them becomes N newlines.
    /// </summary>
    private static string Fold(List<string> content)
    {
        var builder = new StringBuilder(content[0]);
        var pendingBreaks = 0;

        for (var i = 1; i < content.Count; i++)
        {
            if (content[i].Length == 0)
            {
                pendingBreaks++;
                continue;
            }

            if (pendingBreaks == 0)
            {
                builder.Append(' ');
            }
            else
            {
                builder.Append('\n', pendingBreaks);
                pendingBreaks = 0;
            }

            builder.Append(content[i]);
        }

        return builder.ToString();
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
