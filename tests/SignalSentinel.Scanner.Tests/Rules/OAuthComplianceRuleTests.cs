// -----------------------------------------------------------------------
// <copyright file="OAuthComplianceRuleTests.cs" company="Signal Coding Limited">
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

public class OAuthComplianceRuleTests
{
    private readonly OAuthComplianceRule _rule = new();

    [Fact]
    public async Task Evaluate_WithHttpUrl_ReturnsCritical()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "insecure-server",
            Transport = McpTransportType.Http,
            Url = "http://mcp.example.com/mcp"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("No TLS"));
    }

    [Fact]
    public async Task Evaluate_WithStaticAuth_ReturnsHigh()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "static-auth-server",
            Transport = McpTransportType.Http,
            Url = "https://mcp.example.com/mcp",
            Env = new Dictionary<string, string>
            {
                ["API_KEY"] = "sk-something"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.High &&
            f.Title.Contains("Static Authentication"));
    }

    [Fact]
    public async Task Evaluate_WithNoAuth_ReturnsMedium()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "no-auth-server",
            Transport = McpTransportType.Http,
            Url = "https://mcp.example.com/mcp"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.Medium &&
            f.Title.Contains("No Authentication"));
    }

    [Fact]
    public async Task Evaluate_WithStdioServer_SkipsCheck()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "local-server",
            Transport = McpTransportType.Stdio,
            Command = "node",
            Args = ["server.js"]
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_WithWsUrl_ReturnsCritical()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "ws-server",
            Transport = McpTransportType.WebSocket,
            Url = "ws://mcp.example.com/ws"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("No TLS"));
    }

    private static ScanContext CreateContext(McpServerConfig config)
    {
        return new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = config,
                    ServerName = config.Name,
                    Transport = config.Transport.ToString(),
                    ConnectionSuccessful = true,
                    Tools = []
                }
            ]
        };
    }
}
