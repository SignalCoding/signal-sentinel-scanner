// -----------------------------------------------------------------------
// <copyright file="LegacyMcpProtocolRuleTests.cs" company="Signal Coding Limited">
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

public class LegacyMcpProtocolRuleTests
{
    private readonly LegacyMcpProtocolRule _rule = new();

    private static ScanContext MakeContext(string transport, string? protocolVersion, bool connectionSuccessful = true)
    {
        return new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig { Name = "server", Transport = McpTransportType.Http, Url = "https://server" },
                    ServerName = "server",
                    Transport = transport,
                    ProtocolVersion = protocolVersion,
                    ConnectionSuccessful = connectionSuccessful
                }
            ]
        };
    }

    [Fact]
    public async Task Evaluate_CurrentProtocolAndModernTransport_DoesNotFire()
    {
        var context = MakeContext("StreamableHttp", "2026-07-28");

        var findings = await _rule.EvaluateAsync(context);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_OlderProtocolVersion_Fires()
    {
        var context = MakeContext("StreamableHttp", "2025-06-18");

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].RuleId.ShouldBe("SS-INFO-004");
        findings[0].Severity.ShouldBe(Severity.Info);
        findings[0].AstCodes.ShouldContain("AST08");
    }

    [Fact]
    public async Task Evaluate_LegacyHttpTransport_Fires()
    {
        var context = MakeContext("Http", "2026-07-28");

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].RuleId.ShouldBe("SS-INFO-004");
        findings[0].Evidence.ShouldNotBeNull();
        findings[0].Evidence!.ShouldContain("transport: Http");
    }

    [Fact]
    public async Task Evaluate_ConnectionNotSuccessful_DoesNotFire()
    {
        var context = MakeContext("Http", "2025-06-18", connectionSuccessful: false);

        var findings = await _rule.EvaluateAsync(context);

        findings.ShouldBeEmpty();
    }
}
