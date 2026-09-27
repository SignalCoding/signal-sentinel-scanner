// -----------------------------------------------------------------------
// <copyright file="McpLoggingCapabilityAbsentRuleTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Spec: _docs/ai/specs/owasp-full-coverage.md, C4 (SS-INFO-007, "MCP Logging Capability
// Absent"). Modelled on CapabilitySurfaceRuleTests' fixture shape and skip conditions
// (see McpSurfaceRulesTests.cs's Server() helper).
//
// Judgement call: the SS-INFO-007 rule class does not exist yet. Referencing a
// not-yet-existing concrete type would fail to compile and take every other test in the
// assembly down with it. Instead every test here looks the rule up by id through
// RuleEngine.CatalogueRules() (added in #86) and drives it purely through the IRule
// interface, so today it fails cleanly on the "rule not found" assertion, and once the
// implementer adds and registers the rule these same tests exercise its real behaviour
// with no further changes needed.

using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class McpLoggingCapabilityAbsentRuleTests
{
    private const string RuleId = "SS-INFO-007";

    [Fact]
    public async Task LoggingCapabilityAbsent_ConnectedServerWithoutLogging_FiresOnceAtInfo()
    {
        var rule = GetRule();
        var ctx = Server(capabilities: new McpServerCapabilities { Tools = new McpCapabilityInfo() });

        var findings = (await rule.EvaluateAsync(ctx).ConfigureAwait(true)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].RuleId.ShouldBe(RuleId);
        findings[0].Severity.ShouldBe(Severity.Info);
    }

    [Fact]
    public async Task LoggingCapabilityAbsent_ConnectedServerWithLogging_NoFindings()
    {
        var rule = GetRule();
        var ctx = Server(capabilities: new McpServerCapabilities { Logging = new McpCapabilityInfo() });

        var findings = await rule.EvaluateAsync(ctx).ConfigureAwait(true);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task LoggingCapabilityAbsent_ServerFailedToConnect_NoFindings()
    {
        var rule = GetRule();
        var ctx = Server(connected: false, capabilities: new McpServerCapabilities { Tools = new McpCapabilityInfo() });

        var findings = await rule.EvaluateAsync(ctx).ConfigureAwait(true);

        findings.ShouldBeEmpty();
    }

    /// <summary>
    /// Looks the rule up by id in the authoritative catalogue rather than referencing
    /// its (not-yet-existing) concrete type. Fails clearly, naming the missing id, until
    /// the rule is implemented and registered.
    /// </summary>
    private static IRule GetRule()
    {
        var rule = RuleEngine.CatalogueRules()
            .FirstOrDefault(r => string.Equals(r.Id, RuleId, StringComparison.Ordinal));

        rule.ShouldNotBeNull(
            $"{RuleId} (MCP Logging Capability Absent) is not registered in " +
            "RuleEngine.CatalogueRules() - implement and register the rule per spec C4.");

        return rule!;
    }

    private static ScanContext Server(bool connected = true, McpServerCapabilities? capabilities = null) =>
        new()
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig { Name = "test-server" },
                    ServerName = "test-server",
                    Transport = "stdio",
                    ConnectionSuccessful = connected,
                    Capabilities = capabilities
                }
            ]
        };
}
