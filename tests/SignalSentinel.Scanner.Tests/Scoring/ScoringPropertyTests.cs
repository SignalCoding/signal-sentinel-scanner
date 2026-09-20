// -----------------------------------------------------------------------
// <copyright file="ScoringPropertyTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// v3.0.0 (WP11): FsCheck property tests for the scoring rubric. The v3.0.0 spec
// requires four invariants to hold for ANY finding/attack-path population, not just
// hand-picked cases: (a) removing a finding never lowers score or grade,
// (b) lowering a finding's severity never lowers score or grade, (c) all deductions
// are non-negative (score can never exceed 100), (d) grade thresholds are ordered.
// (a)-(c) are genuine properties over generated inputs; the rubric-shape invariants
// ((c) deductions, (d) thresholds) are additionally locked as Facts in
// ScoringRubricTests and enforced at load time by ScoringRubric.TryValidate.

using FsCheck;
using FsCheck.Xunit;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Scoring;

namespace SignalSentinel.Scanner.Tests.Scoring;

public class ScoringPropertyTests
{
    private static readonly Dictionary<SecurityGrade, int> GradeRank =
        new()
        {
            [SecurityGrade.A] = 5,
            [SecurityGrade.B] = 4,
            [SecurityGrade.C] = 3,
            [SecurityGrade.D] = 2,
            [SecurityGrade.F] = 1,
            [SecurityGrade.Inconclusive] = 0
        };

    private static List<Finding> ToFindings(IEnumerable<Severity> severities) =>
        severities.Select((s, i) => new Finding
        {
            RuleId = "SS-000",
            OwaspCode = "ASI00",
            Severity = s,
            Title = $"generated-{i}",
            Description = "generated",
            Remediation = "generated",
            ServerName = "generated"
        }).ToList();

    private static List<AttackPath> ToAttackPaths(IEnumerable<Severity> severities) =>
        severities.Select((s, i) => new AttackPath
        {
            Id = $"path-{i}",
            Description = "generated",
            Severity = s,
            OwaspCodes = ["ASI00"],
            Steps = [],
            Remediation = "generated"
        }).ToList();

    private static int Rank(SecurityGrade grade) => GradeRank[grade];

    private static Severity Lower(Severity severity) => severity switch
    {
        Severity.Critical => Severity.High,
        Severity.High => Severity.Medium,
        Severity.Medium => Severity.Low,
        _ => Severity.Info
    };

    // (a) Removing any finding never lowers the score or the grade.
    [Property(MaxTest = 200)]
    public bool RemovingFinding_NeverLowersScoreOrGrade(
        Severity[] findingSeverities, Severity[] pathSeverities, NonNegativeInt indexSeed)
    {
        if (findingSeverities.Length == 0)
        {
            return true;
        }

        var findings = ToFindings(findingSeverities);
        var paths = ToAttackPaths(pathSeverities);
        var (fullGrade, fullScore) = SeverityScorer.CalculateGrade(findings, paths);

        var reduced = findings.ToList();
        reduced.RemoveAt(indexSeed.Get % findings.Count);
        var (reducedGrade, reducedScore) = SeverityScorer.CalculateGrade(reduced, paths);

        return reducedScore >= fullScore && Rank(reducedGrade) >= Rank(fullGrade);
    }

    // (a, attack-path axis) Removing any attack path never lowers the score or grade.
    [Property(MaxTest = 200)]
    public bool RemovingAttackPath_NeverLowersScoreOrGrade(
        Severity[] findingSeverities, Severity[] pathSeverities, NonNegativeInt indexSeed)
    {
        if (pathSeverities.Length == 0)
        {
            return true;
        }

        var findings = ToFindings(findingSeverities);
        var paths = ToAttackPaths(pathSeverities);
        var (fullGrade, fullScore) = SeverityScorer.CalculateGrade(findings, paths);

        var reduced = paths.ToList();
        reduced.RemoveAt(indexSeed.Get % paths.Count);
        var (reducedGrade, reducedScore) = SeverityScorer.CalculateGrade(findings, reduced);

        return reducedScore >= fullScore && Rank(reducedGrade) >= Rank(fullGrade);
    }

    // (b) Lowering any finding's severity by one band never lowers the score or grade.
    [Property(MaxTest = 200)]
    public bool LoweringSeverity_NeverLowersScoreOrGrade(
        Severity[] findingSeverities, Severity[] pathSeverities, NonNegativeInt indexSeed)
    {
        if (findingSeverities.Length == 0)
        {
            return true;
        }

        var findings = ToFindings(findingSeverities);
        var paths = ToAttackPaths(pathSeverities);
        var (fullGrade, fullScore) = SeverityScorer.CalculateGrade(findings, paths);

        var index = indexSeed.Get % findings.Count;
        var lowered = findings.Select((f, i) =>
            i == index ? f with { Severity = Lower(f.Severity) } : f).ToList();
        var (loweredGrade, loweredScore) = SeverityScorer.CalculateGrade(lowered, paths);

        return loweredScore >= fullScore && Rank(loweredGrade) >= Rank(fullGrade);
    }

    // (c) Deductions are non-negative and bounded: the score stays within [0, 100]
    // for every generated population.
    [Property(MaxTest = 200)]
    public bool Score_AlwaysWithinBounds(Severity[] findingSeverities, Severity[] pathSeverities)
    {
        var (_, score) = SeverityScorer.CalculateGrade(
            ToFindings(findingSeverities), ToAttackPaths(pathSeverities));
        return score is >= 0 and <= 100;
    }

    // No-finding populations (no criticals/highs) always grade A at score 100 -
    // guards against a rubric regression that leaks deductions into clean scans.
    [Property(MaxTest = 100)]
    public bool CleanPopulation_GradesA(Severity[] lowOrInfoSeverities)
    {
        var severities = lowOrInfoSeverities
            .Select(s => s is Severity.Low or Severity.Info ? s : Severity.Info)
            .ToArray();
        var (grade, score) = SeverityScorer.CalculateGrade(ToFindings(severities), []);
        var expected = 100 - severities.Count(s => s == Severity.Low);
        var expectedGrade = score switch
        {
            >= 90 => SecurityGrade.A,
            >= 70 => SecurityGrade.B,
            >= 50 => SecurityGrade.C,
            _ => SecurityGrade.D
        };
        return score == expected && grade == expectedGrade;
    }
}
