// -----------------------------------------------------------------------
// <copyright file="ArgumentParsingTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Config;
using Xunit;

namespace SignalSentinel.Scanner.Tests;

/// <summary>
/// CLI argument parsing outcomes. <c>ParseArguments</c> returns <see langword="null"/>
/// for <c>--help</c> (print usage, exit 0), <see cref="ScanConfig.VersionPrinted"/> for
/// <c>--version</c> (exit 0, nothing more printed) and
/// <see cref="ScanConfig.InvalidArguments"/> for any rejected option (exit 2).
/// </summary>
public class ArgumentParsingTests
{
    [Fact]
    public void Help_ReturnsNull_SoUsageIsPrinted()
    {
        Program.ParseArguments(["--help"]).ShouldBeNull();
    }

    [Fact]
    public void Version_ReturnsVersionSentinel_NotUsage()
    {
        var config = Program.ParseArguments(["--version"]);

        config.ShouldNotBeNull();
        config.ExitSilently.ShouldBeTrue();
        config.ArgumentError.ShouldBeFalse();
    }

    [Theory]
    [InlineData("json", OutputFormat.Json)]
    [InlineData("JSON", OutputFormat.Json)]
    [InlineData("markdown", OutputFormat.Markdown)]
    [InlineData("md", OutputFormat.Markdown)]
    [InlineData("html", OutputFormat.Html)]
    [InlineData("sarif", OutputFormat.Sarif)]
    public void Format_KnownValues_AreAccepted(string value, OutputFormat expected)
    {
        var config = Program.ParseArguments(["--format", value, "--discover"]);

        config.ShouldNotBeNull();
        config.ArgumentError.ShouldBeFalse();
        config.OutputFormat.ShouldBe(expected);
    }

    [Theory]
    [InlineData("text")]
    [InlineData("xml")]
    [InlineData("")]
    public void Format_UnknownValue_IsRejected(string value)
    {
        var config = Program.ParseArguments(["--format", value, "--discover"]);

        config.ShouldNotBeNull();
        config.ArgumentError.ShouldBeTrue();
    }

    [Fact]
    public void UnknownOption_IsRejected()
    {
        var config = Program.ParseArguments(["--bogus-flag"]);

        config.ShouldNotBeNull();
        config.ArgumentError.ShouldBeTrue();
    }
}
