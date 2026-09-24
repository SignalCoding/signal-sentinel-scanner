// -----------------------------------------------------------------------
// <copyright file="GradeBandCeilingTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// v3.0.2 (N5): owner ruling, option B (2026-09-24). SeverityScorer.DetermineGrade
// must never return a grade better than the band implied by the returned score.
// Today the "C: high findings present" branch returns C immediately without
// consulting the score, so a High-heavy scan whose score has collapsed well below
// the C threshold (50) still reports "C". After N5, the threshold band applies as
// a ceiling after the F/D critical rules and the C-by-High rule: a scan scoring
// below thresholds.C grades D even with zero Criticals.
// Spec: _docs/ai/specs/v3.0.2-skill-noise.md N5 (section 5, ruling option B).

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Scoring;
using Xunit;
using FsGen = FsCheck.FSharp.Gen;

namespace SignalSentinel.Scanner.Tests.Scoring;

/// <summary>
/// Wraps a generated finding-severity multiset for property (f) below. A dedicated
/// type (rather than overriding the default <c>Severity[]</c> arbitrary) keeps the
/// biased generator scoped to this one property and out of
/// <c>ScoringPropertyTests</c>' unrelated <c>Severity[]</c> properties.
/// </summary>
public sealed record BiasedSeverityMultiset(IReadOnlyList<Severity> Values);

/// <summary>
/// v3.0.2 (N5) follow-up: the unbiased <c>Severity[]</c> generator used by the first
/// cut of <c>N5_Grade_NeverBetterThanScoreBand</c> only found the counterexample
/// region (highCount &gt;= 1 with the score driven below thresholds.C by enough
/// Mediums) non-deterministically - it depends on shared FsCheck random state that
/// varies with full-suite execution order. This generator biases roughly two thirds
/// of cases into that region on every run, alongside the unconstrained case for
/// coverage of everything else.
/// </summary>
public static class GradeBandGenerators
{
    public static Arbitrary<BiasedSeverityMultiset> BiasedSeverityMultisetArbitrary()
    {
        var allSeverities = new[]
        {
            Severity.Info, Severity.Low, Severity.Medium, Severity.High, Severity.Critical
        };

        // Critical 0, High 1..6, Medium 0..40, Low 0..10, Info 0..5: guarantees
        // highCount >= 1 (so the old C-by-High rule fires) while giving Medium
        // enough range to routinely push the score well below thresholds.C (50).
        var biased =
            from high in FsGen.Choose(1, 6)
            from medium in FsGen.Choose(0, 40)
            from low in FsGen.Choose(0, 10)
            from info in FsGen.Choose(0, 5)
            select BuildSeverities(high, medium, low, info);

        var unconstrained = FsGen.Elements(allSeverities).ArrayOf();

        var mixed = FsGen.Frequency(
        [
            Tuple.Create(2, biased),
            Tuple.Create(1, unconstrained)
        ]);

        return mixed.Select(values => new BiasedSeverityMultiset(values)).ToArbitrary();
    }

    private static Severity[] BuildSeverities(int highCount, int mediumCount, int lowCount, int infoCount)
    {
        var severities = new List<Severity>();
        severities.AddRange(Enumerable.Repeat(Severity.High, highCount));
        severities.AddRange(Enumerable.Repeat(Severity.Medium, mediumCount));
        severities.AddRange(Enumerable.Repeat(Severity.Low, lowCount));
        severities.AddRange(Enumerable.Repeat(Severity.Info, infoCount));
        return [.. severities];
    }
}

public class GradeBandCeilingTests
{
    private static Finding CreateFinding(Severity severity) => new()
    {
        RuleId = "SS-000",
        OwaspCode = "ASI00",
        Severity = severity,
        Title = "generated",
        Description = "generated",
        Remediation = "generated",
        ServerName = "generated"
    };

    private static List<Finding> Findings(Severity severity, int count) =>
        Enumerable.Range(0, count).Select(_ => CreateFinding(severity)).ToList();

    // (a) One High, nothing else: score 90, still grades C. Must stay green -
    // a High-bearing scan whose score is still comfortably above thresholds.C
    // is unaffected by the N5 ceiling.
    [Fact]
    public void N5_OneHigh_NoOtherFindings_GradesCAtScore90()
    {
        var findings = Findings(Severity.High, 1);

        var (grade, score) = SeverityScorer.CalculateGrade(findings, []);

        score.ShouldBe(90);
        grade.ShouldBe(SecurityGrade.C);
    }

    // (b) One High + twenty Medium: 100 - 10 - 60 = 30, below thresholds.C (50).
    // Today's C-by-High rule returns C regardless of score; N5 must grade D.
    [Fact]
    public void N5_OneHighPlusTwentyMedium_ScoreBelowCThreshold_GradesD()
    {
        var findings = Findings(Severity.High, 1).Concat(Findings(Severity.Medium, 20)).ToList();

        var (grade, score) = SeverityScorer.CalculateGrade(findings, []);

        score.ShouldBe(30);
        grade.ShouldBe(SecurityGrade.D);
    }

    // (c) Zero High, seventeen Medium: 100 - 51 = 49, below thresholds.C (50).
    [Fact]
    public void N5_ZeroHigh_SeventeenMedium_ScoreBelowCThreshold_GradesD()
    {
        var findings = Findings(Severity.Medium, 17);

        var (grade, score) = SeverityScorer.CalculateGrade(findings, []);

        score.ShouldBe(49);
        grade.ShouldBe(SecurityGrade.D);
    }

    // (d) Zero High, sixteen Medium: 100 - 48 = 52, at/above thresholds.C (50).
    // Pins the boundary directly under the C threshold - must stay green.
    [Fact]
    public void N5_ZeroHigh_SixteenMedium_ScoreAtCThreshold_GradesC()
    {
        var findings = Findings(Severity.Medium, 16);

        var (grade, score) = SeverityScorer.CalculateGrade(findings, []);

        score.ShouldBe(52);
        grade.ShouldBe(SecurityGrade.C);
    }

    // (e) Critical-findings rules are unchanged by N5: one Critical grades D,
    // two Criticals grade F, regardless of score.
    [Fact]
    public void N5_OneCritical_GradesD()
    {
        var findings = Findings(Severity.Critical, 1);

        var (grade, _) = SeverityScorer.CalculateGrade(findings, []);

        grade.ShouldBe(SecurityGrade.D);
    }

    [Fact]
    public void N5_TwoCriticals_GradesF()
    {
        var findings = Findings(Severity.Critical, 2);

        var (grade, _) = SeverityScorer.CalculateGrade(findings, []);

        grade.ShouldBe(SecurityGrade.F);
    }

    // (g) GetGradeDescription(D) documents the new "score fell below the C
    // threshold" path alongside the existing critical-findings wording.
    [Fact]
    public void N5_GradeDescription_ForD_MentionsScoreBelowCThreshold()
    {
        var description = SeverityScorer.GetGradeDescription(SecurityGrade.D);

        description.ShouldContain("score fell below the C threshold");
    }

    // (f) Property: for any finding multiset (0-60 findings, severities Info..Critical)
    // and no attack paths, the returned grade is never better than the band implied
    // by the returned score under the default thresholds (A>=90, B>=70, C>=50, else D).
    // totalServers/totalSkills are passed non-zero so Inconclusive is never in play.
    private static SecurityGrade BandOfScore(int score) => score switch
    {
        >= 90 => SecurityGrade.A,
        >= 70 => SecurityGrade.B,
        >= 50 => SecurityGrade.C,
        _ => SecurityGrade.D
    };

    private static int BandRank(SecurityGrade grade) => grade switch
    {
        SecurityGrade.A => 4,
        SecurityGrade.B => 3,
        SecurityGrade.C => 2,
        SecurityGrade.D => 1,
        SecurityGrade.F => 0,
        _ => -1
    };

    [Property(MaxTest = 500, Arbitrary = [typeof(GradeBandGenerators)])]
    public bool N5_Grade_NeverBetterThanScoreBand(BiasedSeverityMultiset multiset)
    {
        var bounded = multiset.Values.Take(60).ToArray();
        var findings = bounded.Select(CreateFinding).ToList();

        var (grade, score) = SeverityScorer.CalculateGrade(
            findings, [], totalServers: 1, totalSkills: 1);

        return BandRank(grade) <= BandRank(BandOfScore(score));
    }
}
