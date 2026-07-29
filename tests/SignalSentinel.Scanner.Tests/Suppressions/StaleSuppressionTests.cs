// -----------------------------------------------------------------------
// <copyright file="StaleSuppressionTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Suppressions;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Suppressions;

public class StaleSuppressionTests
{
    private static readonly DateTimeOffset Now = new(2026, 4, 20, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void DetectStale_NoFile_ReturnsEmpty()
    {
        var result = SuppressionManager.DetectStale(null, [], "prod", Now);
        result.ShouldBeEmpty();
    }

    [Fact]
    public void DetectStale_ExpiredEntry_IsReported()
    {
        var file = new SuppressionFile
        {
            Suppressions =
            [
                new SuppressionEntry
                {
                    RuleId = "SS-001",
                    Justification = "ok",
                    ExpiresOn = Now - TimeSpan.FromDays(1),
                }
            ],
        };

        var result = SuppressionManager.DetectStale(file, [], "prod", Now);
        result.Count.ShouldBe(1);
        result[0].Reason.ShouldBe(StaleSuppressionReason.Expired);
    }

    [Fact]
    public void DetectStale_EntryWithNoMatchingFinding_IsReported()
    {
        var file = new SuppressionFile
        {
            Suppressions =
            [
                new SuppressionEntry
                {
                    RuleId = "SS-020",
                    ServerName = "gone-server",
                    Justification = "ok",
                }
            ],
        };

        var findings = new List<Finding>
        {
            MakeFinding("SS-020", "different-server"),
        };

        var result = SuppressionManager.DetectStale(file, findings, "prod", Now);
        result.Count.ShouldBe(1);
        result[0].Reason.ShouldBe(StaleSuppressionReason.NoMatch);
    }

    [Fact]
    public void DetectStale_EntryThatMatches_IsNotReported()
    {
        var file = new SuppressionFile
        {
            Suppressions =
            [
                new SuppressionEntry
                {
                    RuleId = "SS-020",
                    ServerName = "server-a",
                    Justification = "ok",
                }
            ],
        };

        var findings = new List<Finding>
        {
            MakeFinding("SS-020", "server-a"),
        };

        var result = SuppressionManager.DetectStale(file, findings, "prod", Now);
        result.ShouldBeEmpty();
    }

    private static Finding MakeFinding(string ruleId, string serverName) => new()
    {
        RuleId = ruleId,
        OwaspCode = "ASI03",
        Severity = Severity.Critical,
        Title = "x",
        Description = "d",
        Remediation = "r",
        ServerName = serverName,
    };

    [Fact]
    public void DetectStale_EntryForOtherEnvironment_IsSkipped()
    {
        // An entry scoped to "dev" that does not match in a prod scan is not stale,
        // because it's the wrong environment; it may match tomorrow in dev.
        var file = new SuppressionFile
        {
            Suppressions =
            [
                new SuppressionEntry
                {
                    RuleId = "SS-020",
                    Environment = "dev",
                    Justification = "ok",
                }
            ],
        };

        var result = SuppressionManager.DetectStale(file, [], "prod", Now);
        result.ShouldBeEmpty();
    }
}
