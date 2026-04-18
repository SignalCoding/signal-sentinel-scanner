// -----------------------------------------------------------------------
// <copyright file="ScanHistoryManager.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using System.Text.Json.Serialization;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.History;

/// <summary>
/// v2.3.0 scan history. Persists JSON scan reports under
/// <c>.sentinel/history/&lt;iso8601&gt;.json</c> so <c>sentinel-scan diff</c> can
/// compute deltas across runs.
/// </summary>
public static class ScanHistoryManager
{
    private const long MaxHistoryFileBytes = 50 * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: true) }
    };

    /// <summary>
    /// Writes a scan result to the history directory under the working directory's
    /// <c>.sentinel/history/</c> folder. Returns the full path of the file written.
    /// </summary>
    public static async Task<string> SaveAsync(ScanResult result, string? rootDirectory = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);

        var root = rootDirectory ?? Path.Combine(Directory.GetCurrentDirectory(), ".sentinel", "history");
        Directory.CreateDirectory(root);

        var timestamp = result.ScanTimestamp.ToUniversalTime().ToString("yyyyMMddTHHmmssZ", System.Globalization.CultureInfo.InvariantCulture);
        var fileName = $"scan-{timestamp}.json";
        var fullPath = Path.Combine(root, fileName);

        await using var stream = File.Create(fullPath);
        await JsonSerializer.SerializeAsync(stream, result, JsonOptions, cancellationToken);

        return fullPath;
    }

    /// <summary>
    /// Loads a scan result file, used by the diff command.
    /// </summary>
    public static async Task<ScanResult> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Scan history file not found: {path}", path);
        }

        var info = new FileInfo(path);
        if (info.Length > MaxHistoryFileBytes)
        {
            throw new InvalidOperationException($"Scan history file exceeds maximum size: {info.Name}");
        }

        await using var stream = File.OpenRead(path);
        var result = await JsonSerializer.DeserializeAsync<ScanResult>(stream, JsonOptions, cancellationToken)
            ?? throw new InvalidOperationException("Scan history file deserialised to null");
        return result;
    }
}

/// <summary>
/// Computed difference between two scan results (used by <c>sentinel-scan diff</c>).
/// </summary>
public sealed record ScanDiff
{
    public required IReadOnlyList<Finding> Resolved { get; init; }
    public required IReadOnlyList<Finding> Added { get; init; }
    public required IReadOnlyList<Finding> Unchanged { get; init; }
    public required SecurityGrade BaselineGrade { get; init; }
    public required SecurityGrade CurrentGrade { get; init; }
    public required int BaselineScore { get; init; }
    public required int CurrentScore { get; init; }
    public required IReadOnlyDictionary<string, int> AddedContribution { get; init; }
    public required IReadOnlyDictionary<string, int> ResolvedContribution { get; init; }
}

/// <summary>
/// Produces a <see cref="ScanDiff"/> from two scan results.
/// </summary>
public static class ScanDiffer
{
    private static readonly Dictionary<Severity, int> SeverityPoints =
        new()
        {
            [Severity.Critical] = 30,
            [Severity.High] = 15,
            [Severity.Medium] = 7,
            [Severity.Low] = 2,
            [Severity.Info] = 0
        };

    /// <summary>
    /// Computes the diff between baseline and current scans. Identity of a finding is
    /// (RuleId, ServerName, ToolName ?? "", Evidence ?? "").
    /// </summary>
    public static ScanDiff Compute(ScanResult baseline, ScanResult current)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(current);

        string Key(Finding f) =>
            $"{f.RuleId}|{f.ServerName}|{f.ToolName ?? string.Empty}|{f.Evidence ?? string.Empty}";

        var baselineMap = baseline.Findings.ToDictionary(Key, f => f);
        var currentMap = current.Findings.ToDictionary(Key, f => f);

        var resolved = baselineMap
            .Where(kv => !currentMap.ContainsKey(kv.Key))
            .Select(kv => kv.Value)
            .ToList();
        var added = currentMap
            .Where(kv => !baselineMap.ContainsKey(kv.Key))
            .Select(kv => kv.Value)
            .ToList();
        var unchanged = currentMap
            .Where(kv => baselineMap.ContainsKey(kv.Key))
            .Select(kv => kv.Value)
            .ToList();

        var addedContribution = added
            .GroupBy(f => f.RuleId)
            .ToDictionary(g => g.Key, g => -g.Sum(f => SeverityPoints[f.Severity]));
        var resolvedContribution = resolved
            .GroupBy(f => f.RuleId)
            .ToDictionary(g => g.Key, g => g.Sum(f => SeverityPoints[f.Severity]));

        return new ScanDiff
        {
            Resolved = resolved,
            Added = added,
            Unchanged = unchanged,
            BaselineGrade = baseline.Grade,
            CurrentGrade = current.Grade,
            BaselineScore = baseline.Score,
            CurrentScore = current.Score,
            AddedContribution = addedContribution,
            ResolvedContribution = resolvedContribution
        };
    }
}
