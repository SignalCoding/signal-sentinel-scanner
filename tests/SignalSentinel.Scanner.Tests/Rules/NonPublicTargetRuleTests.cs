// -----------------------------------------------------------------------
// <copyright file="NonPublicTargetRuleTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

/// <summary>
/// v2.4.0 A1: SS-INFO-002 Non-Public Target informational rule.
/// </summary>
public class NonPublicTargetRuleTests
{
    private readonly NonPublicTargetRule _rule = new();

    [Theory]
    [InlineData("http://127.0.0.1:5001/mcp")]
    [InlineData("http://localhost/mcp")]
    [InlineData("http://[::1]/mcp")]
    [InlineData("http://10.0.0.7/mcp")]
    [InlineData("http://172.20.1.1/mcp")]
    [InlineData("http://192.168.1.100/mcp")]
    [InlineData("http://mcp.local/mcp")]
    [InlineData("http://dev.internal/mcp")]
    [InlineData("http://169.254.1.1/mcp")]
#pragma warning disable CA1054 // Uri parameters - test fixture data
    public async Task Evaluate_ForNonPublicTarget_EmitsInfoFinding(string url)
#pragma warning restore CA1054
    {
        var ctx = Context(url);
        var findings = (await _rule.EvaluateAsync(ctx)).ToList();
        findings.ShouldContain(f => f.Severity == Severity.Info && f.RuleId == "SS-INFO-002");
    }

    [Theory]
    [InlineData("https://mcp.example.com/mcp")]
    [InlineData("http://198.51.100.10/mcp")]
#pragma warning disable CA1054
    public async Task Evaluate_ForPublicTarget_NoFinding(string url)
#pragma warning restore CA1054
    {
        var ctx = Context(url);
        var findings = await _rule.EvaluateAsync(ctx);
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_ForStdio_NoFinding()
    {
        var ctx = new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig
                    {
                        Name = "local",
                        Transport = McpTransportType.Stdio,
                        Command = "node",
                        Args = ["server.js"],
                    },
                    ServerName = "local",
                    Transport = "Stdio",
                    ConnectionSuccessful = true,
                }
            ]
        };
        var findings = await _rule.EvaluateAsync(ctx);
        findings.ShouldBeEmpty();
    }

    private static ScanContext Context(string url) => new()
    {
        Servers =
        [
            new ServerEnumeration
            {
                ServerConfig = new McpServerConfig
                {
                    Name = "server",
                    Transport = McpTransportType.Http,
                    Url = url,
                },
                ServerName = "server",
                Transport = "Http",
                ConnectionSuccessful = true,
            }
        ]
    };
}
