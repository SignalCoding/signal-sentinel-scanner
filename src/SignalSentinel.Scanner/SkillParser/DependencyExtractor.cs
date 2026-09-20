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
/// so they are never sent to OSV.
/// </summary>
public static partial class DependencyExtractor
{
    private const long MaxManifestBytes = 1024 * 1024;

    /// <summary>Extracts every dependency reference from a skill's instructions and manifests.</summary>
    public static IReadOnlyList<SkillDependency> Extract(SkillDefinition skill)
    {
        ArgumentNullException.ThrowIfNull(skill);

        var results = new List<SkillDependency>();
        results.AddRange(ExtractFromText(skill.Name, skill.InstructionsBody));

        foreach (var file in skill.AdditionalFiles)
        {
            var fileName = Path.GetFileName(file);
            string? ecosystem = fileName switch
            {
                var n when n.Equals("requirements.txt", StringComparison.OrdinalIgnoreCase) => "PyPI",
                var n when n.Equals("package.json", StringComparison.OrdinalIgnoreCase) => "npm",
                var n when n.Equals("pyproject.toml", StringComparison.OrdinalIgnoreCase) => "PyPI",
                _ => null
            };
            if (ecosystem is null)
            {
                continue;
            }

            var content = TryReadBounded(file);
            if (content is null)
            {
                continue;
            }

            results.AddRange(fileName.Equals("package.json", StringComparison.OrdinalIgnoreCase)
                ? ParsePackageJson(skill.Name, fileName, content)
                : ecosystem == "PyPI" && fileName.Equals("pyproject.toml", StringComparison.OrdinalIgnoreCase)
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
            foreach (var token in SplitTokens(match.Groups[1].Value))
            {
                if (TrySplitPinned(token, "==", out var name, out var version))
                {
                    AddIfPlausible(results, skillName, StripExtras(name), version, "PyPI", "instructions");
                    continue;
                }

                // Ranged or bare references ("requests>=2", "requests[security]") are
                // recorded without a version and never queried.
                var bare = StripExtras(token.Split(['<', '>', '=', '~', '!', '[', '('], StringSplitOptions.RemoveEmptyEntries)[0]);
                if (IsPlausibleName(bare))
                {
                    results.Add(new SkillDependency
                    {
                        Name = bare.ToLowerInvariant(), Version = null, Ecosystem = "PyPI",
                        Source = "instructions", SkillName = skillName
                    });
                }
            }
        }

        foreach (Match match in NpmInstallPattern().Matches(text))
        {
            foreach (var token in SplitTokens(match.Groups[1].Value))
            {
                // npm pins use '@' after the name: "pkg@1.2.3", "@scope/pkg@1.2.3".
                var atIndex = token.LastIndexOf('@');
                var pinned = atIndex > 0 && token[(atIndex + 1)..] is { Length: > 0 } candidate
                    && char.IsDigit(candidate[0]);
                var nameToken = atIndex > 0 ? token[..atIndex] : token;
                if (pinned)
                {
                    AddIfPlausible(results, skillName, nameToken, token[(atIndex + 1)..], "npm", "instructions");
                }
                else if (IsPlausibleName(nameToken))
                {
                    // Bare ("pkg") or ranged ("pkg@^1.2", "@scope/pkg@latest") reference.
                    results.Add(new SkillDependency
                    {
                        Name = nameToken.ToLowerInvariant(), Version = null, Ecosystem = "npm",
                        Source = "instructions", SkillName = skillName
                    });
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

            // Strip inline comments and environment markers.
            var hashIndex = line.IndexOf('#');
            if (hashIndex >= 0)
            {
                line = line[..hashIndex].TrimEnd();
            }
            var markerIndex = line.IndexOf(';');
            if (markerIndex >= 0)
            {
                line = line[..markerIndex].TrimEnd();
            }

            if (TrySplitPinned(line, "==", out var name, out var version))
            {
                // "==" only counts when it is the whole operator, not part of ">=".
                AddIfPlausible(results, skillName, StripExtras(name), version.TrimEnd('\\'), "PyPI", source);
            }
            else
            {
                // Bare or ranged ("django>=3.0") reference: record the name, unversioned.
                var bare = StripExtras(
                    line.Split(['<', '>', '=', '~', '!', '[', '('], StringSplitOptions.RemoveEmptyEntries)[0].Trim());
                if (IsPlausibleName(bare))
                {
                    results.Add(new SkillDependency
                    {
                        Name = bare.ToLowerInvariant(), Version = null, Ecosystem = "PyPI",
                        Source = source, SkillName = skillName
                    });
                }
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

            foreach (var section in new[] { "dependencies", "devDependencies" })
            {
                if (!doc.RootElement.TryGetProperty(section, out var deps) ||
                    deps.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (var dep in deps.EnumerateObject())
                {
                    var spec = dep.Value.ValueKind == JsonValueKind.String ? dep.Value.GetString() : null;
                    var version = spec is not null && IsExactVersion(spec) ? spec : null;
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

        return results;
    }

    internal static IReadOnlyList<SkillDependency> ParsePyprojectToml(string skillName, string source, string content)
    {
        // Regex-level TOML: find the [project] section's dependencies array entries.
        var results = new List<SkillDependency>();
        var sectionMatch = PyprojectDependenciesPattern().Match(content);
        if (!sectionMatch.Success)
        {
            return results;
        }

        foreach (Match entry in PyprojectDependencyEntryPattern().Matches(sectionMatch.Groups[1].Value))
        {
            var spec = entry.Groups[1].Success ? entry.Groups[1].Value : entry.Groups[2].Value;
            var equalsIndex = spec.IndexOf("==", StringComparison.Ordinal);
            if (equalsIndex > 0 && spec.IndexOfAny(['<', '>', '~', '!']) < 0)
            {
                var name = StripExtras(spec[..equalsIndex].Trim());
                var version = spec[(equalsIndex + 2)..].Trim().TrimEnd(',', ' ', '"', '\'');
                if (version.Length > 0 && !version.Contains('*'))
                {
                    AddIfPlausible(results, skillName, name, version, "PyPI", source);
                    continue;
                }
            }

            var bareName = StripExtras(
                spec.Split(['=', '<', '>', '~', '!', '[', ' '], StringSplitOptions.RemoveEmptyEntries)[0].Trim());
            if (IsPlausibleName(bareName))
            {
                results.Add(new SkillDependency
                {
                    Name = bareName.ToLowerInvariant(), Version = null, Ecosystem = "PyPI",
                    Source = source, SkillName = skillName
                });
            }
        }

        return results;
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

    private static IEnumerable<string> SplitTokens(string fragment) =>
        fragment.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim().Trim('"', '\'', ';'))
            .Where(t => t.Length > 0 && !t.StartsWith('-'));

    private static bool TrySplitPinned(string token, string separator, out string name, out string version)
    {
        name = string.Empty;
        version = string.Empty;
        var index = token.IndexOf(separator, StringComparison.Ordinal);
        if (index <= 0)
        {
            return false;
        }

        // Reject ranges disguised as pins: "a>=1.2" contains '=' but is not a pin.
        if (token.IndexOfAny(['<', '>', '~', '!']) >= 0)
        {
            return false;
        }

        name = token[..index];
        version = token[(index + separator.Length)..];
        return version.Length > 0 && !version.Contains('*');
    }

    private static bool IsExactVersion(string spec) =>
        spec.Length > 0 && spec.Length <= 64
        && char.IsDigit(spec[0])
        && spec.All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '+' or '_');

    private static string StripExtras(string name)
    {
        var bracketIndex = name.IndexOf('[');
        return (bracketIndex >= 0 ? name[..bracketIndex] : name).Trim();
    }

    private static bool IsPlausibleName(string name) =>
        name.Length is > 1 and <= 128
        && name.All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_' or '/' or '@');

    private static void AddIfPlausible(
        List<SkillDependency> results, string skillName, string name, string version, string ecosystem, string source)
    {
        if (!IsPlausibleName(name) || version.Length > 64)
        {
            return;
        }

        results.Add(new SkillDependency
        {
            Name = name.ToLowerInvariant(), Version = version, Ecosystem = ecosystem,
            Source = source, SkillName = skillName
        });
    }

    // "pip install ..." / "pip3 install ..." up to the end of the shell command.
    [GeneratedRegex(@"\bpip3?\s+install\s+([^\r\n;&|]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PipInstallPattern();

    // "npm install ..." / "npm i ..." up to the end of the shell command.
    [GeneratedRegex(@"\bnpm\s+(?:install|i)\s+([^\r\n;&|]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex NpmInstallPattern();

    // The dependencies array inside a [project] section of pyproject.toml.
    [GeneratedRegex(@"\[project\][^\[]*?dependencies\s*=\s*\[(.*?)\]", RegexOptions.Singleline | RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PyprojectDependenciesPattern();

    [GeneratedRegex(@"""([^""]+)""|'([^']+)'", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PyprojectDependencyEntryPattern();
}
