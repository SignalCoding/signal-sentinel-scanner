// -----------------------------------------------------------------------
// <copyright file="CredentialHygieneRuleTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using FluentAssertions;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class CredentialHygieneRuleTests
{
    private readonly CredentialHygieneRule _rule = new();

    [Fact]
    public async Task Evaluate_WithHardcodedApiKey_ReturnsCritical()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "test-server",
            Transport = McpTransportType.Stdio,
            Command = "node",
            Args = ["server.js"],
            Env = new Dictionary<string, string>
            {
                ["OPENAI_KEY"] = "sk-abcdefghijklmnopqrstuvwxyz1234"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.Should().Contain(f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("Hardcoded Secret"));
    }

    [Fact]
    public async Task Evaluate_WithCredentialEnvVar_ReturnsHigh()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "test-server",
            Transport = McpTransportType.Stdio,
            Command = "node",
            Args = ["server.js"],
            Env = new Dictionary<string, string>
            {
                ["API_TOKEN"] = "some-token-value"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.Should().Contain(f =>
            f.Severity == Severity.High &&
            f.Title.Contains("Credential Passed via Environment Variable"));
    }

    [Fact]
    public async Task Evaluate_WithNoEnvVars_ReturnsNoFindings()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "clean-server",
            Transport = McpTransportType.Stdio,
            Command = "node",
            Args = ["server.js"]
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Evaluate_WithSafeEnvVars_ReturnsNoFindings()
    {
        var context = CreateContext(new McpServerConfig
        {
            Name = "safe-server",
            Transport = McpTransportType.Stdio,
            Command = "node",
            Args = ["server.js"],
            Env = new Dictionary<string, string>
            {
                ["NODE_ENV"] = "production",
                ["PORT"] = "3000"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.Should().BeEmpty();
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
