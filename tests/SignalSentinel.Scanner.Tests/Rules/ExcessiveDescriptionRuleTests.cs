// -----------------------------------------------------------------------
// <copyright file="ExcessiveDescriptionRuleTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Spec: _docs/ai/specs/rule-registry-parity.md, requirement R5. SS-009
// (ExcessiveDescriptionRule) was the only rule with no unit test class, only
// exercised incidentally by fixture regression tests. This covers its three
// length bands (Medium/High/Critical) at, below and above each boundary.
//
// The rule's thresholds (1000/2000/5000 characters) are private consts on
// ExcessiveDescriptionRule itself, not RuleConstants.Limits - there is no matching
// entry there for this rule's length bands, so the boundary values below are
// literals mirroring the rule's own WarningThreshold/CriticalThreshold/
// ExtremThreshold. See the test-report's "judgement calls" section.

using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class ExcessiveDescriptionRuleTests
{
    private readonly ExcessiveDescriptionRule _rule = new();

    // Boundary values mirror ExcessiveDescriptionRule's private
    // WarningThreshold (1000) / CriticalThreshold (2000) / ExtremThreshold (5000).
    private const int WarningThreshold = 1000;
    private const int CriticalThreshold = 2000;
    private const int ExtremThreshold = 5000;

    [Theory]
    [InlineData(WarningThreshold - 1)]
    [InlineData(1)]
    public async Task Evaluate_BelowWarningThreshold_DoesNotFire(int length)
    {
        var ctx = Ctx("some_tool", Description(length));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Theory]
    [InlineData(WarningThreshold)]
    [InlineData(CriticalThreshold - 1)]
    public async Task Evaluate_AtOrAboveWarningThreshold_BelowCritical_FiresMedium(int length)
    {
        var ctx = Ctx("some_tool", Description(length));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.ShouldContain(f => f.RuleId == "SS-009" && f.Severity == Severity.Medium);
        findings.ShouldNotContain(f => f.RuleId == "SS-009" && (f.Severity == Severity.High || f.Severity == Severity.Critical));
    }

    [Theory]
    [InlineData(CriticalThreshold)]
    [InlineData(ExtremThreshold - 1)]
    public async Task Evaluate_AtOrAboveCriticalThreshold_BelowExtreme_FiresHigh(int length)
    {
        var ctx = Ctx("some_tool", Description(length));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.ShouldContain(f => f.RuleId == "SS-009" && f.Severity == Severity.High);
        findings.ShouldNotContain(f => f.RuleId == "SS-009" && (f.Severity == Severity.Medium || f.Severity == Severity.Critical));
    }

    [Theory]
    [InlineData(ExtremThreshold)]
    [InlineData(ExtremThreshold + 1000)]
    public async Task Evaluate_AtOrAboveExtremeThreshold_FiresCritical(int length)
    {
        var ctx = Ctx("some_tool", Description(length));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.ShouldContain(f => f.RuleId == "SS-009" && f.Severity == Severity.Critical);
        findings.ShouldNotContain(f => f.RuleId == "SS-009" && (f.Severity == Severity.Medium || f.Severity == Severity.High));
    }

    [Fact]
    public async Task Evaluate_ConnectionNotSuccessful_DoesNotFire()
    {
        var ctx = Ctx("some_tool", Description(ExtremThreshold), connectionSuccessful: false);

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    /// <summary>
    /// Non-whitespace filler so only the length-band checks are exercised; the
    /// rule's separate whitespace-ratio and description/schema-mismatch checks
    /// require whitespace ratio &gt; 0.5 and a present <c>InputSchema</c>
    /// respectively, neither of which apply here.
    /// </summary>
    private static string Description(int length) => new('a', length);

    private static ScanContext Ctx(string name, string description, bool connectionSuccessful = true)
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
                        Transport = McpTransportType.Stdio,
                        Command = "node",
                        Args = ["server.js"],
                    },
                    ServerName = "server",
                    Transport = "Stdio",
                    ConnectionSuccessful = connectionSuccessful,
                    Tools =
                    [
                        new McpToolDefinition
                        {
                            Name = name,
                            Description = description,
                        }
                    ],
                }
            ]
        };
    }
}
