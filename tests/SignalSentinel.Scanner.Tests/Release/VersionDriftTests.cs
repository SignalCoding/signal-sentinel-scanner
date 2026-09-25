// -----------------------------------------------------------------------
// <copyright file="VersionDriftTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Spec: _docs/ai/specs/release-please-adoption.md item 9 (version drift guard).
// Walks the repository for `\b3\.\d+\.\d+\b` version literals and asserts every
// hit either carries an `x-release-please` marker, sits inside an
// `x-release-please-start...` / `x-release-please-end` block, or is an
// allowlisted dependency pin (`PackageReference` / `uses:`) or the
// DefaultRules.json entry (updated by release-please's json/jsonpath extra-file
// mechanism, which uses no inline marker). Repo root is located the same way
// <see cref="RealWorldSkillFixtures"/> locates the project directory - the
// project directory is three levels above <see cref="AppContext.BaseDirectory"/>
// (bin/&lt;cfg&gt;/&lt;tfm&gt;) - followed by two more levels up
// (tests/&lt;project&gt; -> tests -> repo root).

using System.Text.RegularExpressions;
using Shouldly;
using SignalSentinel.Core;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Release;

public class VersionDriftTests
{
    private static readonly string[] ExcludedDirectorySegments =
        ["bin", "obj", ".git", "_docs", "docs", "tests"];

    // .release-please-manifest.json is the value release-please itself reads and
    // writes on every release PR (release-please-config.json's manifest-file) - it
    // is the source of truth, not a place that can drift, and has no marker syntax.
    private static readonly string[] ExcludedFileNames =
        ["CHANGELOG.md", "SECURITY.md", ".release-please-manifest.json"];

    private static readonly string[] ScannableExtensions =
        [".cs", ".json", ".md", ".yml", ".yaml", ".props", ".csproj", ".sln", ".txt", ".ps1", ".sh"];

    private static readonly Regex VersionLiteral =
        new(@"\b3\.\d+\.\d+\b", RegexOptions.None, TimeSpan.FromMilliseconds(RuleConstants.Limits.RegexTimeoutMs));

    private static readonly Regex ReleaseNotesFileName =
        new(@"^RELEASE_NOTES_.*\.md$", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(RuleConstants.Limits.RegexTimeoutMs));

    private static string RepoRoot
    {
        get
        {
            var projectDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
            var repoRoot = Path.GetFullPath(Path.Combine(projectDir, "..", ".."));

            if (File.Exists(Path.Combine(repoRoot, "signal-sentinel.sln")))
            {
                return repoRoot;
            }

            // Fallback for a copied-to-output layout (mirrors RealWorldSkillFixtures).
            return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        }
    }

    [Fact]
    public void NoUnannotatedVersionLiteralsOutsideAllowlist()
    {
        var repoRoot = RepoRoot;
        var offenders = new List<string>();

        foreach (var file in EnumerateScannableFiles(repoRoot))
        {
            var lines = File.ReadAllLines(file);
            var inMarkerBlock = false;

            for (var lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                var line = lines[lineIndex];

                if (line.Contains("x-release-please-start", StringComparison.Ordinal))
                {
                    inMarkerBlock = true;
                }

                if (line.Contains("x-release-please-end", StringComparison.Ordinal))
                {
                    inMarkerBlock = false;
                    continue;
                }

                if (!SafeIsMatch(VersionLiteral, line))
                {
                    continue;
                }

                if (inMarkerBlock || line.Contains("x-release-please", StringComparison.Ordinal))
                {
                    continue;
                }

                if (line.Contains("PackageReference", StringComparison.Ordinal) ||
                    line.Contains("uses:", StringComparison.Ordinal))
                {
                    continue;
                }

                if (IsJsonExtraFileVersionField(file, line))
                {
                    continue;
                }

                var relativePath = Path.GetRelativePath(repoRoot, file);
                offenders.Add($"{relativePath}:{lineIndex + 1}: {line.Trim()}");
            }
        }

        offenders.ShouldBeEmpty(
            $"Unannotated version literal(s) - add an x-release-please marker or allowlist entry:{Environment.NewLine}" +
            string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The DefaultRules.json "version" field is updated by release-please's
    /// json/jsonpath extra-file mechanism (release-please-config.json), which has
    /// no inline marker syntax for JSON. Only that one field, in that one file, is
    /// exempt.
    /// </summary>
    private static bool IsJsonExtraFileVersionField(string file, string line) =>
        string.Equals(Path.GetFileName(file), "DefaultRules.json", StringComparison.Ordinal) &&
        line.TrimStart().StartsWith("\"version\":", StringComparison.Ordinal);

    private static bool SafeIsMatch(Regex pattern, string input)
    {
        try
        {
            return pattern.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static IEnumerable<string> EnumerateScannableFiles(string repoRoot)
    {
        foreach (var file in Directory.EnumerateFiles(repoRoot, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(repoRoot, file);
            var segments = relativePath.Split(Path.DirectorySeparatorChar);

            if (segments.Any(segment => ExcludedDirectorySegments.Contains(segment, StringComparer.OrdinalIgnoreCase)))
            {
                continue;
            }

            var fileName = Path.GetFileName(file);

            if (ExcludedFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            if (SafeIsMatch(ReleaseNotesFileName, fileName))
            {
                continue;
            }

            var extension = Path.GetExtension(file);

            if (!ScannableExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase) &&
                !fileName.StartsWith("Dockerfile", StringComparison.Ordinal))
            {
                continue;
            }

            yield return file;
        }
    }
}
