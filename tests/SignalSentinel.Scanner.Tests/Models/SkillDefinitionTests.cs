// -----------------------------------------------------------------------
// <copyright file="SkillDefinitionTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Models;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Models;

public class SkillDefinitionTests
{
    [Fact]
    public void CanonicalSkillName_UsesFrontmatterNameWhenPresent()
    {
        var skill = new SkillDefinition
        {
            Name = "  pdf-tools  ",
            InstructionsBody = "x",
            RawContent = "x",
            FilePath = "/skills/pdf-tools-dir-slug/SKILL.md"
        };

        skill.CanonicalSkillName.ShouldBe("pdf-tools");
    }

    [Fact]
    public void CanonicalSkillName_FallsBackToDirectoryNameWhenNameBlank()
    {
        var skill = new SkillDefinition
        {
            Name = string.Empty,
            InstructionsBody = "x",
            RawContent = "x",
            FilePath = "/skills/actual-dir-name/SKILL.md"
        };

        skill.CanonicalSkillName.ShouldBe("actual-dir-name");
    }

    // v2.5.0 (G15b)
    [Fact]
    public void DenyWrite_DefaultsToEmpty()
    {
        var skill = new SkillDefinition
        {
            Name = "plain-skill",
            InstructionsBody = "x",
            RawContent = "x",
            FilePath = "/skills/plain-skill/SKILL.md"
        };

        skill.DenyWrite.ShouldBeEmpty();
    }
}
