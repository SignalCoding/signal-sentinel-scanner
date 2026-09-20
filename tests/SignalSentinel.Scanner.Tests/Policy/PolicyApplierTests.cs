using System;
using System.Collections.Generic;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Policy;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Policy;

public class PolicyApplierTests
{
    private static Finding MakeFinding(string ruleId, Severity severity)
    {
        return new Finding
        {
            RuleId = ruleId,
            OwaspCode = "ASI01",
            Severity = severity,
            Title = "t",
            Description = "d",
            Remediation = "r",
            ServerName = "srv"
        };
    }

    [Fact]
    public void Apply_EmptyPolicy_ReturnsInputUnchanged()
    {
        var findings = new[] { MakeFinding("SS-001", Severity.High) };

        var result = PolicyApplier.Apply(findings, ResolvedPolicy.Default);

        result.ShouldBeSameAs(findings);
    }

    [Fact]
    public void Apply_DisabledRule_DropsFindings()
    {
        var policy = new ResolvedPolicy
        {
            Name = "test",
            DisabledRules = new HashSet<string>(["SS-010"], StringComparer.OrdinalIgnoreCase)
        };
        var findings = new[] { MakeFinding("SS-010", Severity.High), MakeFinding("SS-011", Severity.Low) };

        var result = PolicyApplier.Apply(findings, policy);

        result.Count.ShouldBe(1);
        result[0].RuleId.ShouldBe("SS-011");
    }

    [Fact]
    public void Apply_AbsoluteOverride_AppliesCaseInsensitively()
    {
        var policy = new ResolvedPolicy
        {
            Name = "test",
            SeverityOverrides = new Dictionary<string, Severity>(StringComparer.OrdinalIgnoreCase)
            {
                ["SS-024"] = Severity.High
            }
        };
        var findings = new[] { MakeFinding("ss-024", Severity.Medium) };

        var result = PolicyApplier.Apply(findings, policy);

        result[0].Severity.ShouldBe(Severity.High);
    }

    [Fact]
    public void Apply_BumpOneBandRule_RaisesOneBand()
    {
        var policy = new ResolvedPolicy
        {
            Name = "test",
            BumpOneBandRules = new HashSet<string>(["SS-034"], StringComparer.OrdinalIgnoreCase)
        };
        var findings = new[]
        {
            MakeFinding("SS-034", Severity.Medium),
            MakeFinding("SS-999", Severity.Medium)
        };

        var result = PolicyApplier.Apply(findings, policy);

        result[0].Severity.ShouldBe(Severity.High);
        result[1].Severity.ShouldBe(Severity.Medium);
    }

    [Fact]
    public void Apply_BumpCapsAtCritical()
    {
        var policy = new ResolvedPolicy
        {
            Name = "test",
            BumpOneBandRules = new HashSet<string>(["SS-001"], StringComparer.OrdinalIgnoreCase)
        };

        var result = PolicyApplier.Apply(new[] { MakeFinding("SS-001", Severity.Critical) }, policy);

        result[0].Severity.ShouldBe(Severity.Critical);
    }

    [Fact]
    public void Apply_BumpRaisesInfoToLow()
    {
        var policy = new ResolvedPolicy
        {
            Name = "test",
            BumpAllOneBand = true
        };

        var result = PolicyApplier.Apply(new[] { MakeFinding("SS-INFO-001", Severity.Info) }, policy);

        result[0].Severity.ShouldBe(Severity.Low);
    }

    [Fact]
    public void Apply_AbsoluteOverrideWinsOverBump()
    {
        var policy = new ResolvedPolicy
        {
            Name = "test",
            BumpAllOneBand = true,
            SeverityOverrides = new Dictionary<string, Severity>(StringComparer.OrdinalIgnoreCase)
            {
                ["SS-002"] = Severity.Low
            }
        };

        var result = PolicyApplier.Apply(new[] { MakeFinding("SS-002", Severity.Medium) }, policy);

        result[0].Severity.ShouldBe(Severity.Low);
    }

    [Fact]
    public void Apply_BumpAll_RaisesEveryFinding()
    {
        var policy = new ResolvedPolicy
        {
            Name = "test",
            BumpAllOneBand = true
        };
        var findings = new[]
        {
            MakeFinding("SS-001", Severity.Low),
            MakeFinding("SS-002", Severity.High)
        };

        var result = PolicyApplier.Apply(findings, policy);

        result[0].Severity.ShouldBe(Severity.Medium);
        result[1].Severity.ShouldBe(Severity.Critical);
    }
}
