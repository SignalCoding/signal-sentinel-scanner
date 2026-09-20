// -----------------------------------------------------------------------
// <copyright file="ScoringRubricTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Scoring;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Scoring;

/// <summary>
/// v3.0.0 (WP11): the embedded rubric reproduces the v2.x weights exactly, custom
/// rubrics load and drive <see cref="SeverityScorer"/>, and invalid rubrics fail
/// closed with an error.
/// </summary>
public class ScoringRubricTests
{
    [Fact]
    public void Default_LoadsEmbeddedV2Rubric()
    {
        var rubric = ScoringRubric.Default;

        rubric.Version.ShouldBe("2.0.0");
        rubric.Deductions.CriticalFinding.ShouldBe(25);
        rubric.Deductions.HighFinding.ShouldBe(10);
        rubric.Deductions.MediumFinding.ShouldBe(3);
        rubric.Deductions.LowFinding.ShouldBe(1);
        rubric.Deductions.CriticalAttackPath.ShouldBe(20);
        rubric.Deductions.HighAttackPath.ShouldBe(10);
        rubric.GradeRules.F.CriticalFindingsAtLeast.ShouldBe(2);
        rubric.GradeRules.F.CriticalAttackPathsAtLeast.ShouldBe(2);
        rubric.GradeRules.D.CriticalFindingsAtLeast.ShouldBe(1);
        rubric.GradeRules.D.CriticalAttackPathsAtLeast.ShouldBe(1);
        rubric.GradeRules.C.HighFindingsAtLeast.ShouldBe(1);
        rubric.GradeRules.C.HighAttackPathsAtLeast.ShouldBe(1);
        rubric.GradeThresholds.A.ShouldBe(90);
        rubric.GradeThresholds.B.ShouldBe(70);
        rubric.GradeThresholds.C.ShouldBe(50);
    }

    [Fact]
    public void Default_PassesValidation()
    {
        ScoringRubric.Default.TryValidate(out var error).ShouldBeTrue(error);
    }

    [Fact]
    public void Default_IsCachedSingleton()
    {
        ReferenceEquals(ScoringRubric.Default, ScoringRubric.Default).ShouldBeTrue();
    }

    [Fact]
    public void CalculateGrade_DefaultRubric_MatchesLegacyWeights()
    {
        // One critical finding: 100 - 25 = 75, grade D (single critical).
        var findings = new[] { MakeFinding(Severity.Critical) };
        var (grade, score) = SeverityScorer.CalculateGrade(findings, []);
        score.ShouldBe(75);
        grade.ShouldBe(SecurityGrade.D);
    }

    [Fact]
    public void CalculateGrade_CustomRubric_IsHonored()
    {
        // Double the critical deduction and raise the A threshold: one critical
        // costs 50 and a score of 92 no longer earns an A.
        var rubric = ScoringRubric.Default with
        {
            Deductions = ScoringRubric.Default.Deductions with { CriticalFinding = 50 },
            GradeThresholds = ScoringRubric.Default.GradeThresholds with { A = 95 }
        };

        var (criticalGrade, criticalScore) = SeverityScorer.CalculateGrade(
            [MakeFinding(Severity.Critical)], [], rubric: rubric);
        criticalScore.ShouldBe(50);
        criticalGrade.ShouldBe(SecurityGrade.D);

        var (cleanGrade, cleanScore) = SeverityScorer.CalculateGrade(
            Enumerable.Range(0, 2).Select(_ => MakeFinding(Severity.Medium)).ToList()
                .Append(MakeFinding(Severity.Low)).ToList()
                .Append(MakeFinding(Severity.Low)).ToList(),
            [], rubric: rubric);
        cleanScore.ShouldBe(92); // 100 - 2*3 - 2*1
        cleanGrade.ShouldBe(SecurityGrade.B); // 92 < custom A threshold of 95
    }

    [Fact]
    public void TryLoadFromFile_ValidRubric_RoundTrips()
    {
        var path = WriteTempRubric("""
            {
              "version": "9.9.9-custom",
              "deductions": { "criticalFinding": 40 },
              "gradeThresholds": { "a": 95, "b": 80, "c": 60 }
            }
            """);

        ScoringRubric.TryLoadFromFile(path, out var rubric, out var error).ShouldBeTrue(error);
        rubric.ShouldNotBeNull();
        rubric.Version.ShouldBe("9.9.9-custom");
        rubric.Deductions.CriticalFinding.ShouldBe(40);
        rubric.Deductions.HighFinding.ShouldBe(10); // unspecified knobs keep defaults
        rubric.GradeThresholds.A.ShouldBe(95);
    }

    [Fact]
    public void TryLoadFromFile_MissingFile_Fails()
    {
        ScoringRubric.TryLoadFromFile(
            Path.Combine(Path.GetTempPath(), $"no-such-rubric-{Guid.NewGuid():N}.json"),
            out _, out var error).ShouldBeFalse();
        error.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public void TryLoadFromFile_NotJson_Fails()
    {
        AssertInvalid(WriteTempRubric("this is not json"), "not valid JSON");
    }

    [Fact]
    public void TryLoadFromFile_NegativeDeduction_Fails()
    {
        AssertInvalid(WriteTempRubric("""{ "version": "1", "deductions": { "criticalFinding": -5 } }"""), "non-negative");
    }

    [Fact]
    public void TryLoadFromFile_UnorderedThresholds_Fails()
    {
        AssertInvalid(
            WriteTempRubric("""{ "version": "1", "gradeThresholds": { "a": 60, "b": 70, "c": 50 } }"""),
            "A > B > C");
    }

    [Fact]
    public void TryLoadFromFile_ZeroGradeRuleCount_Fails()
    {
        AssertInvalid(
            WriteTempRubric("""{ "version": "1", "gradeRules": { "d": { "criticalFindingsAtLeast": 0 } } }"""),
            "at least 1");
    }

    private static void AssertInvalid(string path, string expectedErrorFragment)
    {
        ScoringRubric.TryLoadFromFile(path, out _, out var error).ShouldBeFalse();
        error.ShouldNotBeNull().ShouldContain(expectedErrorFragment);
    }

    private static string WriteTempRubric(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), $"rubric-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        return path;
    }

    private static Finding MakeFinding(Severity severity) => new()
    {
        RuleId = "SS-000",
        OwaspCode = "ASI00",
        Severity = severity,
        Title = "test",
        Description = "test",
        Remediation = "test",
        ServerName = "test"
    };
}
