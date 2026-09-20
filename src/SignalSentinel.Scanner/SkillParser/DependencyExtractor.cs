// -----------------------------------------------------------------------
// <copyright file="DependencyExtractor.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using System.Text.RegularExpressions;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Osv;

namespace SignalSentinel.Scanner.SkillParser;

/// <summary>
/// v3.0.0 (WP6): extracts package dependency references from a skill — from its
/// instruction text (<c>pip install a==1.2</c>, <c>npm install a@1.2</c>) and from
/// bundled manifests (requirements.txt, package.json, pyproject.toml, regex-level).
/// Unpinned or ranged references are recorded but carry no <see cref="SkillDependency.Version"/>,
/// so they are never sent to OSV. Extraction is best-effort and never throws on
/// hostile or malformed input.
/// </summary>
public static partial class DependencyExtractor
{
    private const long MaxManifestBytes = 1024 * 1024;

    private static readonly char[] PipOperatorChars = ['<', '>', '=', '~', '!', '[', '('];

    private static readonly char[] TokenTrimChars = ['"', '\'', ';', '`', ',', ')', '('];

    // pip options that consume the following token as their value.
    private static readonly HashSet<string> PipValueFlags = new(StringComparer.Ordinal)
    {
        "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target",
        "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--platform",
        "--python-version", "--implementation", "--abi", "--root", "--prefix", "--src",
        "--log", "--proxy", "--cache-dir", "--trusted-host", "--cert", "--client-cert",
        "--config-settings", "-C", "--report", "--progress-bar", "--timeout", "--retries",
        "--exists-action", "--use-feature", "--use-deprecated"
    };

    // npm options that consume the following token as their value.
    private static readonly HashSet<string> NpmValueFlags = new(StringComparer.Ordinal)
    {
        "--prefix", "--registry", "--tag", "-w", "--workspace", "--omit", "--include",
        "--loglevel", "--cache", "--userconfig", "--install-strategy", "--otp", "-C"
    };

    /// <summary>Extracts every dependency reference from a skill's instructions and manifests.</summary>
    public static IReadOnlyList<SkillDependency> Extract(SkillDefinition skill)
    {
        ArgumentNullException.ThrowIfNull(skill);

        var results = new List<SkillDependency>();
        results.AddRange(ExtractFromText(skill.Name, skill.InstructionsBody));

        // SkillReader records additional files by bare name; resolve them against the
        // skill's own directory so a manifest in the process CWD is never mistaken for
        // one bundled with the skill.
        var skillDirectory = SafeDirectoryName(skill.FilePath);

        foreach (var file in skill.AdditionalFiles)
        {
            var fileName = Path.GetFileName(file);
            var isPackageJson = fileName.Equals("package.json", StringComparison.OrdinalIgnoreCase);
            var isPyproject = fileName.Equals("pyproject.toml", StringComparison.OrdinalIgnoreCase);
            var isRequirements = fileName.Equals("requirements.txt", StringComparison.OrdinalIgnoreCase);
            if (!isPackageJson && !isPyproject && !isRequirements)
            {
                continue;
            }

            var path = ResolveManifestPath(skillDirectory, file);
            if (path is null)
            {
                continue;
            }

            var content = TryReadBounded(path);
            if (content is null)
            {
                continue;
            }

            results.AddRange(isPackageJson
                ? ParsePackageJson(skill.Name, fileName, content)
                : isPyproject
                    ? ParsePyprojectToml(skill.Name, fileName, content)
                    : ParseRequirementsTxt(skill.Name, fileName, content));
        }

        return results;
    }

    /// <summary>Extracts pip/npm install references from free text (instructions, scripts).</summary>
    internal static IReadOnlyList<SkillDependency> ExtractFromText(string skillName, string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        var results = new List<SkillDependency>();

        foreach (Match match in PipInstallPattern().Matches(text))
        {
            // "requests == 2.31.0" is legal PEP 508; collapse whitespace around operators
            // so it tokenises as one pinned reference rather than three fragments.
            var fragment = SpacedOperatorPattern().Replace(match.Groups[1].Value, "$1");

            foreach (var token in SplitTokens(fragment, PipValueFlags))
            {
                if (TrySplitPinned(token, out var name, out var version))
                {
                    AddIfPlausible(results, skillName, StripExtras(name), version, "PyPI", "instructions");
                    continue;
                }

                // Ranged or bare references ("requests>=2", "requests[security]") are
                // recorded without a version and never queried.
                AddBareIfPlausible(results, skillName, StripExtras(FirstSegment(token, PipOperatorChars)), "PyPI", "instructions");
            }
        }

        foreach (Match match in NpmInstallPattern().Matches(text))
        {
            foreach (var token in SplitTokens(match.Groups[1].Value, NpmValueFlags))
            {
                // Paths, URLs, git specs and tarballs are not registry packages.
                if (token.Contains(':', StringComparison.Ordinal)
                    || token.StartsWith('.') || token.StartsWith('/') || token.StartsWith('~')
                    || token.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // npm pins use '@' after the name: "pkg@1.2.3", "@scope/pkg@1.2.3".
                var atIndex = token.LastIndexOf('@');
                var nameToken = atIndex > 0 ? token[..atIndex] : token;
                var spec = atIndex > 0 ? token[(atIndex + 1)..] : string.Empty;
                if (spec.Length > 0 && IsPlausibleVersion(spec))
                {
                    AddIfPlausible(results, skillName, nameToken, spec, "npm", "instructions");
                }
                else
                {
                    // Bare ("pkg") or ranged ("pkg@^1.2", "pkg@1.x", "@scope/pkg@latest") reference.
                    AddBareIfPlausible(results, skillName, nameToken, "npm", "instructions");
                }
            }
        }

        return results;
    }

    internal static IReadOnlyList<SkillDependency> ParseRequirementsTxt(string skillName, string source, string content)
    {
        var results = new List<SkillDependency>();
        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('-'))
            {
                continue;
            }

            // Strip inline comments, environment markers and per-line options (--hash=...).
            line = CutAt(line, '#');
            line = CutAt(line, ';');
            var optionIndex = line.IndexOf(" -", StringComparison.Ordinal);
            if (optionIndex >= 0)
            {
                line = line[..optionIndex];
            }

            // PEP 508 permits whitespace around operators; the remaining text has none
            // that matters, so drop it all to normalise "requests == 2.31.0".
            line = RemoveWhitespace(line).TrimEnd('\\');
            if (line.Length == 0)
            {
                continue;
            }

            if (TrySplitPinned(line, out var name, out var version))
            {
                AddIfPlausible(results, skillName, StripExtras(name), version, "PyPI", source);
            }
            else
            {
                // Bare or ranged ("django>=3.0") reference: record the name, unversioned.
                AddBareIfPlausible(results, skillName, StripExtras(FirstSegment(line, PipOperatorChars)), "PyPI", source);
            }
        }

        return results;
    }

    internal static IReadOnlyList<SkillDependency> ParsePackageJson(string skillName, string source, string content)
    {
        var results = new List<SkillDependency>();
        try
        {
            using var doc = JsonDocument.Parse(content, new JsonDocumentOptions
            {
                MaxDepth = 16,
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip
            });

            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return results;
            }

            foreach (var section in new[] { "dependencies", "devDependencies" })
            {
                if (!doc.RootElement.TryGetProperty(section, out var deps) ||
                    deps.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (var dep in deps.EnumerateObject())
                {
                    if (!IsPlausibleName(dep.Name))
                    {
                        continue;
                    }

                    var spec = dep.Value.ValueKind == JsonValueKind.String ? dep.Value.GetString() : null;
                    var version = spec is not null && IsPlausibleVersion(spec) ? spec : null;
                    results.Add(new SkillDependency
                    {
                        Name = dep.Name.ToLowerInvariant(), Version = version, Ecosystem = "npm",
                        Source = source, SkillName = skillName
                    });
                }
            }
        }
        catch (JsonException)
        {
            // A malformed manifest is not a dependency signal.
        }
        catch (InvalidOperationException)
        {
            // Unexpected JSON shape (non-object root, wrong value kinds): ignore.
        }

        return results;
    }

    internal static IReadOnlyList<SkillDependency> ParsePyprojectToml(string skillName, string source, string content)
    {
        // Regex-level TOML: find the [project] section's dependencies array entries.
        var results = new List<SkillDependency>();
        var arrayBody = FindProjectDependenciesArray(content);
        if (arrayBody is null)
        {
            return results;
        }

        foreach (Match entry in PyprojectDependencyEntryPattern().Matches(arrayBody))
        {
            var spec = RemoveWhitespace(entry.Groups[1].Success ? entry.Groups[1].Value : entry.Groups[2].Value);
            spec = CutAt(spec, ';');
            if (spec.Length == 0)
            {
                continue;
            }

            if (TrySplitPinned(spec, out var name, out var version))
            {
                AddIfPlausible(results, skillName, StripExtras(name), version, "PyPI", source);
                continue;
            }

            AddBareIfPlausible(results, skillName, StripExtras(FirstSegment(spec, PipOperatorChars)), "PyPI", source);
        }

        return results;
    }

    /// <summary>
    /// Locates the body of <c>dependencies = [ ... ]</c> inside the <c>[project]</c> table,
    /// honouring nested brackets (<c>pkg[extra]==1.0</c>) and quoted strings.
    /// </summary>
    private static string? FindProjectDependenciesArray(string content)
    {
        var header = ProjectSectionHeaderPattern().Match(content);
        if (!header.Success)
        {
            return null;
        }

        var sectionStart = header.Index + header.Length;
        var nextHeader = AnySectionHeaderPattern().Match(content, sectionStart);
        var section = nextHeader.Success ? content[sectionStart..nextHeader.Index] : content[sectionStart..];

        var keyMatch = DependenciesKeyPattern().Match(section);
        if (!keyMatch.Success)
        {
            return null;
        }

        var depth = 1;
        var inQuote = '\0';
        var bodyStart = keyMatch.Index + keyMatch.Length;
        for (var i = bodyStart; i < section.Length; i++)
        {
            var c = section[i];
            if (inQuote != '\0')
            {
                if (c == inQuote)
                {
                    inQuote = '\0';
                }

                continue;
            }

            switch (c)
            {
                case '"' or '\'':
                    inQuote = c;
                    break;
                case '[':
                    depth++;
                    break;
                case ']':
                    depth--;
                    if (depth == 0)
                    {
                        return section[bodyStart..i];
                    }

                    break;
            }
        }

        // Unterminated array: take what is there.
        return section[bodyStart..];
    }

    private static string? SafeDirectoryName(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return null;
        }

        try
        {
            return Path.GetDirectoryName(Path.GetFullPath(filePath));
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException
            or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static string? ResolveManifestPath(string? skillDirectory, string file)
    {
        try
        {
            if (skillDirectory is null)
            {
                // No anchor: refuse rather than fall back to the process CWD.
                return null;
            }

            // Rooted or relative, a manifest only counts when it lives inside the skill.
            var candidate = Path.GetFullPath(Path.IsPathRooted(file) ? file : Path.Combine(skillDirectory, file));
            var root = skillDirectory.EndsWith(Path.DirectorySeparatorChar)
                ? skillDirectory
                : skillDirectory + Path.DirectorySeparatorChar;
            return candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase) ? candidate : null;
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException
            or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static string? TryReadBounded(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > MaxManifestBytes || info.Length == 0)
            {
                return null;
            }

            return File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whitespace-splits a shell fragment, dropping option flags and the value token of
    /// options that take one (<c>-r requirements.txt</c>, <c>--registry url</c>).
    /// </summary>
    private static IEnumerable<string> SplitTokens(string fragment, HashSet<string> valueFlags)
    {
        var raw = fragment.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        var skipNext = false;
        foreach (var item in raw)
        {
            if (skipNext)
            {
                skipNext = false;
                continue;
            }

            var token = item.Trim().Trim(TokenTrimChars);
            if (token.Length == 0)
            {
                continue;
            }

            if (token.StartsWith('-'))
            {
                // "--flag=value" carries its value inline; "--flag value" consumes the next token.
                skipNext = valueFlags.Contains(token) && !token.Contains('=', StringComparison.Ordinal);
                continue;
            }

            yield return token;
        }
    }

    private static bool TrySplitPinned(string token, out string name, out string version)
    {
        name = string.Empty;
        version = string.Empty;
        var index = token.IndexOf("==", StringComparison.Ordinal);
        if (index <= 0)
        {
            return false;
        }

        // Reject ranges disguised as pins: "a>=1.2" contains '=' but is not a pin; and
        // "a===1.0" is the arbitrary-equality operator, not a version pin.
        if (token.IndexOfAny(['<', '>', '~', '!']) >= 0 || token.Contains("===", StringComparison.Ordinal))
        {
            return false;
        }

        name = token[..index];
        version = token[(index + 2)..];
        return IsPlausibleVersion(version);
    }

    private static string FirstSegment(string value, char[] separators)
    {
        var parts = value.Split(separators, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 0 ? string.Empty : parts[0].Trim();
    }

    private static string CutAt(string value, char marker)
    {
        var index = value.IndexOf(marker);
        return index >= 0 ? value[..index].TrimEnd() : value;
    }

    private static string RemoveWhitespace(string value) =>
        string.Concat(value.Where(c => !char.IsWhiteSpace(c)));

    /// <summary>
    /// An exact, queryable version: starts with a digit, no wildcard or "x" segment, only
    /// version-safe characters. Anything else is treated as a range and left unpinned.
    /// </summary>
    private static bool IsPlausibleVersion(string spec) =>
        spec.Length > 0 && spec.Length <= 64
        && char.IsDigit(spec[0])
        && spec.All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '+' or '_')
        && !spec.Split('.').Any(part => part.Equals("x", StringComparison.OrdinalIgnoreCase));

    private static string StripExtras(string name)
    {
        var bracketIndex = name.IndexOf('[');
        return (bracketIndex >= 0 ? name[..bracketIndex] : name).Trim();
    }

    /// <summary>
    /// A registry-shaped package name: letters/digits with <c>. - _</c>, at least one letter,
    /// and scoped npm names only as <c>@scope/name</c>. Rejects flag values, paths, and
    /// stray version fragments.
    /// </summary>
    private static bool IsPlausibleName(string name)
    {
        if (name.Length is < 2 or > 128 || !name.Any(char.IsLetter))
        {
            return false;
        }

        if (name[0] is '.' or '-' or '_' or '/' || name[^1] is '.' or '-' or '_' or '/')
        {
            return false;
        }

        if (name[0] == '@')
        {
            var slash = name.IndexOf('/');
            if (slash < 2 || slash == name.Length - 1 || name.IndexOf('@', 1) >= 0)
            {
                return false;
            }
        }
        else if (name.Contains('@') || name.Contains('/'))
        {
            return false;
        }

        // Registry names are ASCII; anything else is prose or a confusable, not a package.
        return name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '/' or '@');
    }

    private static void AddIfPlausible(
        List<SkillDependency> results, string skillName, string name, string version, string ecosystem, string source)
    {
        if (!IsPlausibleName(name) || !IsPlausibleVersion(version))
        {
            return;
        }

        results.Add(new SkillDependency
        {
            Name = name.ToLowerInvariant(), Version = version, Ecosystem = ecosystem,
            Source = source, SkillName = skillName
        });
    }

    private static void AddBareIfPlausible(
        List<SkillDependency> results, string skillName, string name, string ecosystem, string source)
    {
        if (!IsPlausibleName(name))
        {
            return;
        }

        results.Add(new SkillDependency
        {
            Name = name.ToLowerInvariant(), Version = null, Ecosystem = ecosystem,
            Source = source, SkillName = skillName
        });
    }

    // "pip install ..." / "pip3 install ..." / "python -m pip install ..." up to the end of the
    // shell command (a closing backtick ends inline Markdown code).
    [GeneratedRegex(@"\bpip3?\s+install\s+([^\r\n;&|`]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PipInstallPattern();

    // "npm install ..." / "npm i ..." / "npm add ..." up to the end of the shell command.
    [GeneratedRegex(@"\bnpm\s+(?:install|i|add)\s+([^\r\n;&|`]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex NpmInstallPattern();

    // Whitespace around a PEP 440 comparison operator.
    [GeneratedRegex(@"[ \t]*(===|==|>=|<=|~=|!=|<|>)[ \t]*", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex SpacedOperatorPattern();

    // Multiline '$' matches before '\n' only, so tolerate a preceding '\r' for CRLF files.
    [GeneratedRegex(@"^[ \t]*\[project\][ \t]*(?:#[^\r\n]*)?\r?$", RegexOptions.Multiline | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex ProjectSectionHeaderPattern();

    [GeneratedRegex(@"^[ \t]*\[{1,2}[^\r\n\]]*\]{1,2}[ \t]*(?:#[^\r\n]*)?\r?$", RegexOptions.Multiline | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex AnySectionHeaderPattern();

    [GeneratedRegex(@"^[ \t]*dependencies[ \t]*=[ \t]*\[", RegexOptions.Multiline | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex DependenciesKeyPattern();

    [GeneratedRegex(@"""([^""]+)""|'([^']+)'", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PyprojectDependencyEntryPattern();
}
