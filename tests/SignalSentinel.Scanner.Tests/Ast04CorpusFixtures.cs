// -----------------------------------------------------------------------
// <copyright file="Ast04CorpusFixtures.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.Tests;

/// <summary>
/// ast04-metadata-integrity: locates the vendored AST04 labelled corpus under
/// <c>Fixtures/Ast04Corpus</c> (see that directory's <c>NOTICE.md</c> for
/// provenance). Resolution mirrors <see cref="RealWorldSkillFixtures"/>: the
/// project directory (three levels above <see cref="AppContext.BaseDirectory"/>,
/// i.e. <c>bin/&lt;cfg&gt;/&lt;tfm&gt;</c>) is tried first so an IDE run and a
/// <c>dotnet test</c> run both see the same files, with the copied-to-output
/// location as a fallback.
/// </summary>
internal static class Ast04CorpusFixtures
{
    private const string DirectoryName = "Ast04Corpus";

    /// <summary>Vulnerable fixture directory names (AST04 corpus positives).</summary>
    internal static readonly string[] VulnerableFixtures =
    [
        "V1-yaml-frontmatter-injection",
        "V3-json-metadata-injection",
        "V5-toml-metadata-injection",
        "V7-permission-understating",
        "V9-risk-tier-spoofing"
    ];

    /// <summary>Matched benign control fixture directory names (AST04 corpus negatives).</summary>
    internal static readonly string[] ControlFixtures =
    [
        "C2-yaml-frontmatter-injection",
        "C4-json-metadata-injection",
        "C6-toml-metadata-injection",
        "C8-permission-understating",
        "C10-risk-tier-spoofing"
    ];

    /// <summary>Absolute path of the corpus directory.</summary>
    internal static string Dir
    {
        get
        {
            var projectRelative = Path.Combine(
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..")),
                "Fixtures",
                DirectoryName);

            if (Directory.Exists(projectRelative))
            {
                return projectRelative;
            }

            return Path.Combine(AppContext.BaseDirectory, "Fixtures", DirectoryName);
        }
    }

    /// <summary>Absolute path of one fixture directory inside the corpus.</summary>
    internal static string FixtureDir(string fixtureName) => Path.Combine(Dir, fixtureName);
}
