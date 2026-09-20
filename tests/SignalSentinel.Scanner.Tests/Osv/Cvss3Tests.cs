using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Osv;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Osv;

public class Cvss3Tests
{
    [Theory]
    // Canonical 9.8 network wormable vector.
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.Critical)]
    // Scope-changed full impact is a perfect 10.
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, Severity.Critical)]
    // FIRST's canonical reflected-XSS example.
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, Severity.Medium)]
    // No impact at all scores zero.
    [InlineData("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, Severity.Info)]
    // Version 3.0 also accepted.
    [InlineData("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.5, Severity.High)]
    public void TryComputeBaseScore_KnownVectors(string vector, double expected, Severity severity)
    {
        var score = Cvss3.BaseScore(vector);

        score.ShouldNotBeNull();
        score.Value.ShouldBe(expected, 0.05);
        Cvss3.ToSeverity(score.Value).ShouldBe(severity);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not a vector")]
    [InlineData("CVSS:3.1/AV:N/AC:L")]                        // too short
    [InlineData("CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")] // bad metric value
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H")]     // missing S
    public void TryComputeBaseScore_Malformed_ReturnsNull(string? vector)
    {
        Cvss3.BaseScore(vector).ShouldBeNull();
    }

    [Fact]
    public void BaseScore_ToleratesMissingCvssPrefix()
    {
        var score = Cvss3.BaseScore("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

        score.ShouldNotBeNull();
        score.Value.ShouldBe(9.8, 0.05);
    }

    [Fact]
    public void LowBand_AboveZero_BelowFour()
    {
        var score = Cvss3.BaseScore("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

        score.ShouldNotBeNull();
        score.Value.ShouldBeGreaterThan(0);
        score.Value.ShouldBeLessThan(4.0);
        Cvss3.ToSeverity(score.Value).ShouldBe(Severity.Low);
    }
}
