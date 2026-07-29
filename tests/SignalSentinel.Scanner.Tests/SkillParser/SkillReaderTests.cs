// -----------------------------------------------------------------------
// <copyright file="SkillReaderTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillParser;

public class SkillReaderTests
{
    private static async Task<string> WriteTempSkillAsync(string content)
    {
        var dir = Path.Combine(Path.GetTempPath(), "sentinel-skillreader-tests-" + Guid.NewGuid());
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "SKILL.md");
        await File.WriteAllTextAsync(path, content).ConfigureAwait(false);
        return path;
    }

    // v2.5.0 (G15b): flat dotted-key form (permissions.deny_write).
    [Fact]
    public async Task ReadAsync_WithDottedDenyWrite_PopulatesDenyWrite()
    {
        var content = """
            ---
            name: memory-safe-skill
            description: A skill that promises not to touch memory files
            permissions.deny_write: [AGENTS.md, MEMORY.md]
            ---
            Reads config, never writes to identity files.
            """;
        var path = await WriteTempSkillAsync(content);

        var skill = await SkillReader.ReadAsync(path);

        skill.ShouldNotBeNull();
        skill!.DenyWrite.ShouldBe(["AGENTS.md", "MEMORY.md"]);
    }

    // v2.5.0 (G15b): nested block form (permissions:\n  deny_write:\n    - X).
    [Fact]
    public async Task ReadAsync_WithNestedDenyWriteBlock_PopulatesDenyWrite()
    {
        var content = """
            ---
            name: memory-safe-skill
            description: A skill that promises not to touch memory files
            permissions:
              deny_write:
                - AGENTS.md
            ---
            Reads config, never writes to identity files.
            """;
        var path = await WriteTempSkillAsync(content);

        var skill = await SkillReader.ReadAsync(path);

        skill.ShouldNotBeNull();
        skill!.DenyWrite.ShouldBe(["AGENTS.md"]);
    }

    [Fact]
    public async Task ReadAsync_WithoutDenyWrite_ReturnsEmptyList()
    {
        var content = """
            ---
            name: plain-skill
            description: No permission declarations
            ---
            Does something ordinary.
            """;
        var path = await WriteTempSkillAsync(content);

        var skill = await SkillReader.ReadAsync(path);

        skill.ShouldNotBeNull();
        skill!.DenyWrite.ShouldBeEmpty();
    }
}
