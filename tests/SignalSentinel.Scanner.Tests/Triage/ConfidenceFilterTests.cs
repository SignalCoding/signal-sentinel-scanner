using System;
using System.Collections.Generic;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Triage;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Triage;

public class ConfidenceFilterTests
{
    private static Finding MakeFinding(Severity severity, double? confidence)
    {
        return new Finding
        {
            RuleId = "SS-099",
            OwaspCode = "ASI01",
            Severity = severity,
            Title = "t",
            Description = "d",
            Remediation = "r",
            ServerName = "srv",
            Confidence = confidence
        };
    }

    [Fact]
    public void Apply_ZeroMinAndNoTriage_ReturnsInputUnchanged()
    {
        var findings = new[] { MakeFinding(Severity.High, 0.3), MakeFinding(Severity.Low, 0.9) };
        var result = ConfidenceFilter.Apply(findings, 0, false);
        Assert.Same(findings, result);
    }

    [Fact]
    public void Apply_MinConfidence_DropsBelowThreshold()
    {
        var findings = new[]
        {
            MakeFinding(Severity.High, 0.3),
            MakeFinding(Severity.High, 0.8)
        };
        var result = ConfidenceFilter.Apply(findings, 0.7, false);
        Assert.Single(result);
        Assert.Equal(0.8, result[0].Confidence);
    }

    [Fact]
    public void Apply_TriageMode_DemotesBelowDemotionThreshold()
    {
        var findings = new[] { MakeFinding(Severity.Critical, 0.5) };
        var result = ConfidenceFilter.Apply(findings, 0, true);
        Assert.Single(result);
        Assert.Equal(Severity.Low, result[0].Severity);
    }

    [Fact]
    public void Apply_TriageMode_DoesNotDemoteAboveThreshold()
    {
        var findings = new[] { MakeFinding(Severity.Critical, 0.9) };
        var result = ConfidenceFilter.Apply(findings, 0, true);
        Assert.Equal(Severity.Critical, result[0].Severity);
    }

    [Fact]
    public void Apply_NullConfidence_TreatedAsOne()
    {
        var findings = new[] { MakeFinding(Severity.Medium, null) };
        var result = ConfidenceFilter.Apply(findings, 0.9, false);
        Assert.Single(result);
    }

    [Fact]
    public void Apply_InvalidMinConfidence_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ConfidenceFilter.Apply(Array.Empty<Finding>(), 1.5, false));
    }
}
