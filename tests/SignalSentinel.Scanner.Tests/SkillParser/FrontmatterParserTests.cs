// -----------------------------------------------------------------------
// <copyright file="FrontmatterParserTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using FluentAssertions;
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

        result.HasFrontmatter.Should().BeTrue();
        result.GetField("name").Should().Be("test-skill");
        result.GetField("description").Should().Be("A test skill");
        result.GetField("context").Should().Be("full");
        result.Body.Should().Contain("# Instructions");
        result.Body.Should().Contain("Do something useful.");
    }

    [Fact]
    public void Parse_WithNoFrontmatter_ReturnsBodyOnly()
    {
        var content = "# Just Markdown\nNo frontmatter here.";

        var result = FrontmatterParser.Parse(content);

        result.HasFrontmatter.Should().BeFalse();
        result.Fields.Should().BeEmpty();
        result.Body.Should().Be(content);
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

        result.GetField("name").Should().Be("my-skill");
        result.GetField("description").Should().Be("A quoted description");
    }

    [Fact]
    public void Parse_WithEmptyContent_ReturnsEmptyResult()
    {
        var result = FrontmatterParser.Parse("");

        result.HasFrontmatter.Should().BeFalse();
        result.Body.Should().BeEmpty();
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

        result.GetField("nonexistent").Should().BeNull();
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

        result.RawFrontmatter.Should().Contain("name: test");
        result.RawFrontmatter.Should().Contain("custom_key: custom_value");
    }
}
