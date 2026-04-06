// -----------------------------------------------------------------------
// <copyright file="FrontmatterParserTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillParser;

public class FrontmatterParserTests
{
    [Fact]
    public void Parse_WithValidFrontmatter_ExtractsFields()
    {
        var content = """
            ---
            name: test-skill
            description: A test skill
            context: full
            ---
            # Instructions
            Do something useful.
            """;

        var result = FrontmatterParser.Parse(content);

        result.HasFrontmatter.ShouldBeTrue();
        result.GetField("name").ShouldBe("test-skill");
        result.GetField("description").ShouldBe("A test skill");
        result.GetField("context").ShouldBe("full");
        result.Body.ShouldContain("# Instructions");
        result.Body.ShouldContain("Do something useful.");
    }

    [Fact]
    public void Parse_WithNoFrontmatter_ReturnsBodyOnly()
    {
        var content = "# Just Markdown\nNo frontmatter here.";

        var result = FrontmatterParser.Parse(content);

        result.HasFrontmatter.ShouldBeFalse();
        result.Fields.ShouldBeEmpty();
        result.Body.ShouldBe(content);
    }

    [Fact]
    public void Parse_WithQuotedValues_StripsQuotes()
    {
        var content = """
            ---
            name: "my-skill"
            description: 'A quoted description'
            ---
            Body content.
            """;

        var result = FrontmatterParser.Parse(content);

        result.GetField("name").ShouldBe("my-skill");
        result.GetField("description").ShouldBe("A quoted description");
    }

    [Fact]
    public void Parse_WithEmptyContent_ReturnsEmptyResult()
    {
        var result = FrontmatterParser.Parse("");

        result.HasFrontmatter.ShouldBeFalse();
        result.Body.ShouldBeEmpty();
    }

    [Fact]
    public void Parse_WithMissingField_ReturnsNull()
    {
        var content = """
            ---
            name: test
            ---
            Body.
            """;

        var result = FrontmatterParser.Parse(content);

        result.GetField("nonexistent").ShouldBeNull();
    }

    [Fact]
    public void Parse_PreservesRawFrontmatter()
    {
        var content = """
            ---
            name: test
            custom_key: custom_value
            ---
            Body.
            """;

        var result = FrontmatterParser.Parse(content);

        result.RawFrontmatter.ShouldNotBeNull();
        result.RawFrontmatter!.ShouldContain("name: test");
        result.RawFrontmatter.ShouldContain("custom_key: custom_value");
    }
}
