// -----------------------------------------------------------------------
// <copyright file="MissingAuthProbeRuleTests.cs" company="Signal Coding Limited">
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
/// v2.4.0 A2: behavioural auth-probe rule. Consumes the
/// <see cref="AuthProbeResult"/> captured during enumeration.
/// </summary>
public class MissingAuthProbeRuleTests
{
    private readonly MissingAuthProbeRule _rule = new();

    [Fact]
    public async Task Evaluate_WhenAuthEnforced_NoFinding()
    {
        var ctx = CreateContext(new AuthProbeResult
        {
            StatusCode = 401,
            WwwAuthenticate = "Bearer realm=\"mcp\"",
            AuthEnforced = true,
            Classification = "enforced",
        });

        var findings = await _rule.EvaluateAsync(ctx);
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_WhenAnonymousInitializeSucceeded_EmitsMedium()
    {
        var ctx = CreateContext(new AuthProbeResult
        {
            StatusCode = 200,
            AnonymousInitializeSucceeded = true,
            Classification = "open",
        });

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.Medium &&
            f.Title.Contains("Unauthenticated"));
    }

    [Fact]
    public async Task Evaluate_WhenProbeUnclear_EmitsLow()
    {
        var ctx = CreateContext(new AuthProbeResult
        {
            StatusCode = 403,
            Classification = "unclear",
            Note = "403 without WWW-Authenticate",
        });

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.Low &&
            f.Title.Contains("Unclear"));
    }

    [Fact]
    public async Task Evaluate_WhenStatusCodeZero_NoFinding()
    {
        // v2.4.1 (G2): StatusCode 0 means the probe request never completed
        // (connectivity failure), not an auth-posture observation - must not
        // produce an "Auth Posture Unclear" finding.
        var ctx = CreateContext(new AuthProbeResult
        {
            StatusCode = 0,
            Classification = "unclear",
            Note = "Probe failed: HttpRequestException.",
        });

        var findings = await _rule.EvaluateAsync(ctx);
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_WhenProbeNull_NoFinding()
    {
        var ctx = CreateContext(probe: null);

        var findings = await _rule.EvaluateAsync(ctx);
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_WhenLoopbackTarget_NoFinding()
    {
        var ctx = CreateContext(
            probe: new AuthProbeResult
            {
                StatusCode = 200,
                AnonymousInitializeSucceeded = true,
                Classification = "open",
            },
            url: "http://127.0.0.1:5001/mcp");

        var findings = await _rule.EvaluateAsync(ctx);
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_WhenStdio_NoFinding()
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

    private static ScanContext CreateContext(AuthProbeResult? probe, string url = "https://mcp.example.com/mcp")
    {
        return new ScanContext
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
                    AuthProbe = probe,
                }
            ]
        };
    }
}
