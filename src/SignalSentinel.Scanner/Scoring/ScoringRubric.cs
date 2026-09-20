// -----------------------------------------------------------------------
// <copyright file="ScoringRubric.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;

namespace SignalSentinel.Scanner.Scoring;

/// <summary>
/// v3.0.0 (WP11): versioned, auditable scoring rubric. The default rubric is the
/// embedded <c>scoring-rubric-v2.0.0.json</c> (weights identical to the hard-coded
/// v2.x algorithm); <c>--rubric &lt;path&gt;</c> substitutes a custom file.
/// </summary>
public sealed record ScoringRubric
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private static readonly Lazy<ScoringRubric> EmbeddedDefault = new(LoadEmbedded);

    /// <summary>Schema/rubric version, emitted as <c>RubricVersion</c> in every report.</summary>
    public string Version { get; init; } = "2.0.0";

    public RubricDeductions Deductions { get; init; } = new();

    public RubricGradeRules GradeRules { get; init; } = new();

    public RubricGradeThresholds GradeThresholds { get; init; } = new();

    /// <summary>The embedded v2.0.0 rubric shipped with the scanner.</summary>
    public static ScoringRubric Default => EmbeddedDefault.Value;

    /// <summary>
    /// Loads and validates a custom rubric from a JSON file (<c>--rubric</c>).
    /// </summary>
    public static bool TryLoadFromFile(string path, out ScoringRubric? rubric, out string? error)
    {
        rubric = null;
        string json;
        try
        {
            json = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = $"Rubric file could not be read: {path} ({ex.Message})";
            return false;
        }

        return TryParse(json, path, out rubric, out error);
    }

    /// <summary>
    /// Validates a rubric: deductions and grade-rule counts must be non-negative and
    /// grade thresholds strictly ordered (A &gt; B &gt; C &gt;= 0, all &lt;= 100).
    /// </summary>
    public bool TryValidate(out string? error)
    {
        error = null;

        if (string.IsNullOrWhiteSpace(Version))
        {
            error = "Rubric 'version' must be a non-empty string.";
            return false;
        }

        if (Deductions.CriticalFinding < 0 || Deductions.HighFinding < 0
            || Deductions.MediumFinding < 0 || Deductions.LowFinding < 0
            || Deductions.CriticalAttackPath < 0 || Deductions.HighAttackPath < 0)
        {
            error = "Rubric deductions must all be non-negative.";
            return false;
        }

        if (GradeRules.F.CriticalFindingsAtLeast < 1 || GradeRules.F.CriticalAttackPathsAtLeast < 1
            || GradeRules.D.CriticalFindingsAtLeast < 1 || GradeRules.D.CriticalAttackPathsAtLeast < 1
            || GradeRules.C.HighFindingsAtLeast < 1 || GradeRules.C.HighAttackPathsAtLeast < 1)
        {
            error = "Rubric grade-rule counts must all be at least 1.";
            return false;
        }

        if (GradeThresholds.A is < 0 or > 100 || GradeThresholds.B is < 0 or > 100
            || GradeThresholds.C is < 0 or > 100
            || GradeThresholds.A <= GradeThresholds.B || GradeThresholds.B <= GradeThresholds.C)
        {
            error = "Rubric grade thresholds must satisfy 100 >= A > B > C >= 0.";
            return false;
        }

        return true;
    }

    private static bool TryParse(string json, string name, out ScoringRubric? rubric, out string? error)
    {
        rubric = null;
        error = null;

        ScoringRubric? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<ScoringRubric>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            error = $"Rubric '{name}' is not valid JSON: {ex.Message}";
            return false;
        }

        if (parsed is null)
        {
            error = $"Rubric '{name}' is empty.";
            return false;
        }

        if (!parsed.TryValidate(out error))
        {
            error = $"Rubric '{name}' is invalid: {error}";
            return false;
        }

        rubric = parsed;
        return true;
    }

    private static ScoringRubric LoadEmbedded()
    {
        var assembly = typeof(ScoringRubric).Assembly;
        var resourceName = assembly
            .GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(".Scoring.scoring-rubric-v2.0.0.json", StringComparison.OrdinalIgnoreCase));

        if (resourceName is null)
        {
            throw new InvalidOperationException(
                "Embedded scoring rubric 'scoring-rubric-v2.0.0.json' is missing from this build.");
        }

        using var stream = assembly.GetManifestResourceStream(resourceName)!;
        using var reader = new StreamReader(stream);
        if (!TryParse(reader.ReadToEnd(), "embedded v2.0.0", out var rubric, out var error))
        {
            throw new InvalidOperationException($"Embedded scoring rubric failed validation: {error}");
        }

        return rubric!;
    }
}

/// <summary>Per-signal score deductions (points subtracted from 100 per occurrence).</summary>
public sealed record RubricDeductions
{
    public int CriticalFinding { get; init; } = 25;
    public int HighFinding { get; init; } = 10;
    public int MediumFinding { get; init; } = 3;
    public int LowFinding { get; init; } = 1;
    public int CriticalAttackPath { get; init; } = 20;
    public int HighAttackPath { get; init; } = 10;
}

/// <summary>Count-driven grade rules, checked F, then D, then C (first match wins).</summary>
public sealed record RubricGradeRules
{
    public RubricCriticalRule F { get; init; } = new() { CriticalFindingsAtLeast = 2, CriticalAttackPathsAtLeast = 2 };
    public RubricCriticalRule D { get; init; } = new();
    public RubricHighRule C { get; init; } = new();
}

/// <summary>F/D rule thresholds; F also fires when one critical finding AND one critical path co-occur.</summary>
public sealed record RubricCriticalRule
{
    public int CriticalFindingsAtLeast { get; init; } = 1;
    public int CriticalAttackPathsAtLeast { get; init; } = 1;
}

/// <summary>C rule thresholds.</summary>
public sealed record RubricHighRule
{
    public int HighFindingsAtLeast { get; init; } = 1;
    public int HighAttackPathsAtLeast { get; init; } = 1;
}

/// <summary>Score-driven thresholds for the count-clean grades (A &gt; B &gt; C).</summary>
public sealed record RubricGradeThresholds
{
    public int A { get; init; } = 90;
    public int B { get; init; } = 70;
    public int C { get; init; } = 50;
}
