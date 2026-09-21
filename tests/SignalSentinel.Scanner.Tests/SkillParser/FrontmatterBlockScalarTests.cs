// -----------------------------------------------------------------------
// <copyright file="FrontmatterBlockScalarTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// v3.0.1 (F1): YAML block scalars in SKILL.md frontmatter.
//
// The v3.0.0 line-regex parser has no block-scalar support, so "description: >"
// parses to the literal value ">" and every continuation line is dropped. On the
// 2026-09-21 scan of anthropics/skills this made SS-012 (and every other
// description consumer) reason about a one-character description. Folded (>)
// joins continuation lines with a single space; literal (|) joins them with a
// newline; chomping indicators -/+ control the trailing newline.
// Spec: _docs/ai/specs/v3.0.1-skill-false-positives.md F1.

using Shouldly;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillParser;

public class FrontmatterBlockScalarTests
{
    private static string Doc(string frontmatterBody) =>
        "---\n" + frontmatterBody + "---\n# Instructions\n\nDo the thing.\n";

    // ---- Folded scalars (>) ------------------------------------------------

    [Fact]
    public void Parse_FoldedScalar_JoinsContinuationLinesWithSingleSpace()
    {
        var content = Doc(
            "name: folded-skill\n" +
            "description: >\n" +
            "  first line\n" +
            "  second line\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("description").ShouldBe("first line second line\n");
    }

    [Fact]
    public void Parse_FoldedScalar_IsNeverTheIndicatorItself()
    {
        var content = Doc(
            "name: folded-skill\n" +
            "description: >\n" +
            "  a real description of what this skill does\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("description").ShouldNotBe(">");
        result.GetField("description").ShouldNotBeNullOrWhiteSpace();
        result.GetField("description")!.ShouldContain("a real description");
    }

    [Fact]
    public void Parse_FoldedScalar_BlankLineBecomesNewline()
    {
        // YAML 1.2 folding: a blank line inside a folded block is a paragraph break.
        var content = Doc(
            "description: >\n" +
            "  para one line a\n" +
            "  para one line b\n" +
            "\n" +
            "  para two\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("description").ShouldBe("para one line a para one line b\npara two\n");
    }

    [Fact]
    public void Parse_FoldedScalar_StripChomping_DropsTrailingNewline()
    {
        var content = Doc(
            "description: >-\n" +
            "  first line\n" +
            "  second line\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("description").ShouldBe("first line second line");
    }

    [Fact]
    public void Parse_FoldedScalar_KeepChomping_KeepsTrailingNewlines()
    {
        var content = Doc(
            "description: >+\n" +
            "  first line\n" +
            "\n" +
            "\n" +
            "next: value\n");

        var result = FrontmatterParser.Parse(content);

        var description = result.GetField("description");
        description.ShouldNotBeNull();
        description.ShouldStartWith("first line\n");
        description.ShouldEndWith("\n\n");
        result.GetField("next").ShouldBe("value");
    }

    // ---- Literal scalars (|) ----------------------------------------------

    [Fact]
    public void Parse_LiteralScalar_JoinsContinuationLinesWithNewline()
    {
        var content = Doc(
            "description: |\n" +
            "  line one\n" +
            "  line two\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("description").ShouldBe("line one\nline two\n");
    }

    [Fact]
    public void Parse_LiteralScalar_StripChomping_DropsTrailingNewline()
    {
        var content = Doc(
            "description: |-\n" +
            "  line one\n" +
            "  line two\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("description").ShouldBe("line one\nline two");
        result.GetField("description").ShouldNotBe("|-");
    }

    [Fact]
    public void Parse_LiteralScalar_PreservesRelativeIndentation()
    {
        var content = Doc(
            "description: |-\n" +
            "  step one\n" +
            "    nested detail\n" +
            "  step two\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("description").ShouldBe("step one\n  nested detail\nstep two");
    }

    // ---- Block boundaries --------------------------------------------------

    [Fact]
    public void Parse_BlockScalar_EndsAtFirstColumnZeroKey()
    {
        var content = Doc(
            "name: bounded\n" +
            "description: >\n" +
            "  folded text continues\n" +
            "  over two lines\n" +
            "license: Complete terms in LICENSE.txt\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("name").ShouldBe("bounded");
        result.GetField("description").ShouldBe("folded text continues over two lines\n");
        result.GetField("license").ShouldBe("Complete terms in LICENSE.txt");
    }

    [Fact]
    public void Parse_BlockScalar_ContinuationLinesAreNotParsedAsFields()
    {
        // A continuation line that happens to look like "key: value" must stay
        // inside the scalar, not become a frontmatter field of its own.
        var content = Doc(
            "description: |-\n" +
            "  TRIGGER: read this before answering\n" +
            "  SKIP: when another provider is named\n");

        var result = FrontmatterParser.Parse(content);

        result.Fields.ShouldNotContainKey("TRIGGER");
        result.Fields.ShouldNotContainKey("SKIP");
        result.GetField("description").ShouldBe(
            "TRIGGER: read this before answering\nSKIP: when another provider is named");
    }

    [Fact]
    public void Parse_BlockScalar_FollowedByListField_StillParsesTheList()
    {
        var content = Doc(
            "description: >\n" +
            "  a folded description\n" +
            "capabilities:\n" +
            "  - read\n" +
            "  - write\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("description").ShouldBe("a folded description\n");
        result.GetListField("capabilities").ShouldBe(["read", "write"]);
    }

    // ---- Must-not-regress --------------------------------------------------

    [Fact]
    public void Parse_BlockScalar_LeavesRawFrontmatterUntouched()
    {
        // SS-026 reads RawFrontmatter; it must stay the verbatim YAML text.
        var content = Doc(
            "name: raw-check\n" +
            "description: >\n" +
            "  folded line one\n" +
            "  folded line two\n");

        var result = FrontmatterParser.Parse(content);

        result.RawFrontmatter.ShouldNotBeNull();
        result.RawFrontmatter.ShouldContain("description: >");
        result.RawFrontmatter.ShouldContain("  folded line one");
        result.RawFrontmatter.ShouldContain("  folded line two");
    }

    [Fact]
    public void Parse_BlockScalar_DoesNotChangeTheBody()
    {
        var content = Doc(
            "description: |\n" +
            "  literal line\n");

        var result = FrontmatterParser.Parse(content);

        result.Body.ShouldStartWith("# Instructions");
        result.Body.ShouldContain("Do the thing.");
    }

    [Fact]
    public void Parse_SingleLineValues_StillParseUnchanged()
    {
        var content = Doc(
            "name: plain-skill\n" +
            "description: A plain single-line description\n" +
            "permissions.deny_write: [AGENTS.md, CLAUDE.md]\n");

        var result = FrontmatterParser.Parse(content);

        result.GetField("name").ShouldBe("plain-skill");
        result.GetField("description").ShouldBe("A plain single-line description");
        result.GetListField("permissions.deny_write").ShouldBe(["AGENTS.md", "CLAUDE.md"]);
    }

    [Fact]
    public void Parse_OversizedBlockScalar_RespectsTheValueCap()
    {
        var huge = string.Join(string.Empty, Enumerable.Repeat("  padding padding padding padding\n", 400));
        var content = Doc("description: |\n" + huge);

        var result = FrontmatterParser.Parse(content);

        (result.GetField("description")?.Length ?? 0).ShouldBeLessThanOrEqualTo(10_000);
    }

    // ---- Real corpus documents --------------------------------------------

    [Fact]
    public void Parse_AcademyGuideFixture_FoldedDescriptionBecomesProse()
    {
        var content = File.ReadAllText(RealWorldSkillFixtures.SkillFile("academy-guide"));

        var result = FrontmatterParser.Parse(content);

        var description = result.GetField("description");
        description.ShouldNotBeNull();
        description.ShouldNotBe(">");
        description.ShouldStartWith("Stop and check this skill");
        description.ShouldContain("Claude Academy");
        description.ShouldNotContain("\n  "); // folded, not left as raw indented lines
    }

    [Fact]
    public void Parse_ClaudeApiFixture_LiteralDescriptionBecomesProse()
    {
        var content = File.ReadAllText(RealWorldSkillFixtures.SkillFile("claude-api"));

        var result = FrontmatterParser.Parse(content);

        var description = result.GetField("description");
        description.ShouldNotBeNull();
        description.ShouldNotBe("|-");
        description.ShouldStartWith("Reference for the Claude API");
        description.ShouldContain("TRIGGER");
        result.GetField("license").ShouldBe("Complete terms in LICENSE.txt");
    }
}
