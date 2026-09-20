// -----------------------------------------------------------------------
// <copyright file="RemoteUrlPolicyTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Net;
using Shouldly;
using SignalSentinel.Scanner.Config;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Config;

public class RemoteUrlPolicyTests
{
    [Theory]
    [InlineData("https://mcp.example.com/mcp")]
    [InlineData("http://mcp.example.com:8080/mcp")]
    [InlineData("wss://mcp.example.com/ws")]
    [InlineData("ws://mcp.example.com/ws")]
    public void IsValidSyntax_AllowedSchemes_ReturnsTrue(string candidate)
    {
        RemoteUrlPolicy.IsValidSyntax(candidate).ShouldBeTrue();
    }

    [Theory]
    [InlineData("ftp://mcp.example.com/")]
    [InlineData("file:///etc/passwd")]
    [InlineData("javascript:alert(1)")]
    [InlineData("mcp.example.com/mcp")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void IsValidSyntax_DisallowedOrMalformed_ReturnsFalse(string? candidate)
    {
        RemoteUrlPolicy.IsValidSyntax(candidate).ShouldBeFalse();
    }

    [Fact]
    public void IsValidSyntax_OverLength_ReturnsFalse()
    {
        var candidate = "https://example.com/" + new string('a', RemoteUrlPolicy.MaxUrlLength);
        RemoteUrlPolicy.IsValidSyntax(candidate).ShouldBeFalse();
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.1.2.3")]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.254")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]
    [InlineData("::ffff:10.0.0.1")]
    public void IsPrivateAddress_PrivateRanges_ReturnsTrue(string ip)
    {
        RemoteUrlPolicy.IsPrivateAddress(IPAddress.Parse(ip)).ShouldBeTrue();
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.15.0.1")]
    [InlineData("172.32.0.1")]
    [InlineData("192.169.0.1")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("::ffff:8.8.8.8")]
    public void IsPrivateAddress_PublicRanges_ReturnsFalse(string ip)
    {
        RemoteUrlPolicy.IsPrivateAddress(IPAddress.Parse(ip)).ShouldBeFalse();
    }

    [Theory]
    [InlineData("http://127.0.0.1:3000/mcp")]
    [InlineData("http://localhost:3000/mcp")]
    [InlineData("http://[::1]:3000/mcp")]
    [InlineData("http://192.168.0.10/mcp")]
    public void TargetsPrivateNetwork_LiteralPrivateHosts_ReturnsTrue(string candidate)
    {
        RemoteUrlPolicy.TargetsPrivateNetwork(candidate).ShouldBeTrue();
    }

    [Fact]
    public void TargetsPrivateNetwork_LiteralPublicHost_ReturnsFalse()
    {
        RemoteUrlPolicy.TargetsPrivateNetwork("https://8.8.8.8/mcp").ShouldBeFalse();
    }

    [Fact]
    public void TargetsPrivateNetwork_UnresolvableHost_ReturnsFalse()
    {
        // Do not block on DNS failure; the connection attempt will report the real error.
        RemoteUrlPolicy.TargetsPrivateNetwork("https://this-host-does-not-exist.invalid/mcp")
            .ShouldBeFalse();
    }
}
