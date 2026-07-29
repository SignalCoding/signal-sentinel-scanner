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

    // v2.4.0 A2: the "no visible auth in env" heuristic was replaced by the
    // MissingAuthProbeRule, which asks the server directly. A plain https URL
    // with no env vars is therefore no longer a finding on its own - see
    // MissingAuthProbeRuleTests for the behavioural equivalents.
    [Fact]
    public async Task Evaluate_WithHttpsAndNoEnv_DoesNotEmitNoAuthFinding()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "no-auth-server",
            Transport = McpTransportType.Http,
            Url = "https://mcp.example.com/mcp"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("No Authentication"));
    }

    // v2.4.0 A1: loopback targets are exempt from the TLS rule.
    [Fact]
    public async Task Evaluate_WithHttpLoopback_DoesNotEmitTlsFinding()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "dev-server",
            Transport = McpTransportType.Http,
            Url = "http://127.0.0.1:5001/mcp"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("No TLS"));
    }

    [Fact]
    public async Task Evaluate_WithHttpLocalhost_DoesNotEmitTlsFinding()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "local",
            Transport = McpTransportType.Http,
            Url = "http://localhost/mcp"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("No TLS"));
    }

    [Fact]
    public async Task Evaluate_WithHttpRfc1918_DoesNotEmitTlsFinding()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "vpn-server",
            Transport = McpTransportType.Http,
            Url = "http://10.0.1.5:8080/mcp"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("No TLS"));
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

    // v2.5.0 (G13b): MCP 2026-07-28 authorization hardening advisory.
    [Fact]
    public async Task Evaluate_WithAuthEnforced_ReturnsHardeningAdvisory()
    {
        var context = CreateContext(
            new McpServerConfig
            {
                Name = "auth-server",
                Transport = McpTransportType.Http,
                Url = "https://mcp.example.com/mcp"
            },
            authProbe: new AuthProbeResult { AuthEnforced = true, StatusCode = 401, Classification = "enforced" });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("Authorization Hardening Not Verified"));
    }

    [Fact]
    public async Task Evaluate_WithoutAuthProbe_DoesNotReturnHardeningAdvisory()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "no-probe-server",
            Transport = McpTransportType.Http,
            Url = "https://mcp.example.com/mcp"
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Authorization Hardening Not Verified"));
    }

    [Fact]
    public async Task Evaluate_WithAuthNotEnforced_DoesNotReturnHardeningAdvisory()
    {
        var context = CreateContext(
            new McpServerConfig
            {
                Name = "open-server",
                Transport = McpTransportType.Http,
                Url = "https://mcp.example.com/mcp"
            },
            authProbe: new AuthProbeResult { AuthEnforced = false, AnonymousInitializeSucceeded = true, StatusCode = 200, Classification = "open" });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Authorization Hardening Not Verified"));
    }

    private static ScanContext CreateContext(McpServerConfig config, AuthProbeResult? authProbe = null)
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
                    Tools = [],
                    AuthProbe = authProbe
                }
            ]
        };
    }
}
