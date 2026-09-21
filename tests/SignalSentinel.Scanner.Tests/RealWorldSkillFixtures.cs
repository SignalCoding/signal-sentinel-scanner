// -----------------------------------------------------------------------
// <copyright file="RealWorldSkillFixtures.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.Tests;

/// <summary>
/// v3.0.1 (F14): locates the real-world skill regression corpus under
/// <c>Fixtures/RealWorldSkills</c>. Resolution mirrors
/// <c>SegmentationRegressionTests</c>: the project directory (three levels above
/// <see cref="AppContext.BaseDirectory"/>, i.e. <c>bin/&lt;cfg&gt;/&lt;tfm&gt;</c>) is
/// tried first so an IDE run and a <c>dotnet test</c> run both see the same files,
/// with the copied-to-output location as a fallback.
/// </summary>
internal static class RealWorldSkillFixtures
{
    private const string DirectoryName = "RealWorldSkills";

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

    /// <summary>Absolute path of one <c>SKILL.md</c> inside the corpus.</summary>
    internal static string SkillFile(string skillName) =>
        Path.Combine(Dir, skillName, "SKILL.md");
}
