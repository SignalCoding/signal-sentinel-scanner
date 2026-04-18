// -----------------------------------------------------------------------
// <copyright file="SuppressionManager.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Suppressions;

/// <summary>
/// Loads suppression files, matches them against findings, and produces annotated
/// findings that carry <see cref="SuppressionMetadata"/> when matched.
/// </summary>
public static class SuppressionManager
{
    private const long MaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Loads a suppression file. Returns null when the file does not exist, throws
    /// <see cref="InvalidOperationException"/> on malformed content.
    /// </summary>
    public static async Task<SuppressionFile?> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            return null;
        }

        var info = new FileInfo(path);
        if (info.Length > MaxFileSizeBytes)
        {
            throw new InvalidOperationException(
                $"Suppression file exceeds maximum size ({MaxFileSizeBytes / (1024 * 1024)} MB): {info.Name}");
        }

        await using var stream = File.OpenRead(path);
        try
        {
            var file = await JsonSerializer.DeserializeAsync<SuppressionFile>(stream, JsonOptions, cancellationToken)
                ?? throw new InvalidOperationException("Suppression file parsed to null");

            if (!string.Equals(file.Version, "1.0", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Unsupported suppression-file schema version '{file.Version}'. Expected '1.0'.");
            }

            foreach (var entry in file.Suppressions)
            {
                if (string.IsNullOrWhiteSpace(entry.RuleId))
                {
                    throw new InvalidOperationException("Suppression entry is missing 'ruleId'.");
                }
                if (string.IsNullOrWhiteSpace(entry.Justification))
                {
                    throw new InvalidOperationException($"Suppression for '{entry.RuleId}' is missing 'justification'.");
                }
            }

            return file;
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"Suppression file is malformed JSON: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Saves a suppression file to disk (pretty-printed JSON).
    /// </summary>
    public static async Task SaveAsync(string path, SuppressionFile file, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(file);

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, file, JsonOptions, cancellationToken);
    }

    /// <summary>
    /// Applies suppression entries to a list of findings. Matching entries produce a
    /// finding with <see cref="Finding.Suppression"/> populated; expired suppressions
    /// still emit the finding but mark it as expired.
    /// </summary>
    public static IReadOnlyList<Finding> Apply(
        IReadOnlyList<Finding> findings,
        SuppressionFile? file,
        string environment,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentException.ThrowIfNullOrWhiteSpace(environment);

        if (file is null || file.Suppressions.Count == 0)
        {
            return findings;
        }

        var result = new List<Finding>(findings.Count);
        foreach (var finding in findings)
        {
            var match = FindMatch(file.Suppressions, finding, environment);
            if (match is null)
            {
                result.Add(finding);
                continue;
            }

            var expired = match.ExpiresOn is not null && match.ExpiresOn.Value < now;
            result.Add(finding with
            {
                Suppression = new SuppressionMetadata
                {
                    Justification = match.Justification,
                    ApprovedBy = match.ApprovedBy,
                    ApprovedOn = match.ApprovedOn,
                    ExpiresOn = match.ExpiresOn,
                    Expired = expired
                }
            });
        }

        return result;
    }

    /// <summary>
    /// Produces a new file with the given entry appended. Used by <c>--accept</c>.
    /// </summary>
    public static SuppressionFile Append(SuppressionFile? existing, SuppressionEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var list = new List<SuppressionEntry>(existing?.Suppressions ?? []);
        list.Add(entry);
        return new SuppressionFile { Version = "1.0", Suppressions = list };
    }

    private static SuppressionEntry? FindMatch(
        IReadOnlyList<SuppressionEntry> entries,
        Finding finding,
        string environment)
    {
        foreach (var entry in entries)
        {
            if (!string.Equals(entry.RuleId, finding.RuleId, StringComparison.Ordinal))
            {
                continue;
            }
            if (entry.ServerName is not null &&
                !string.Equals(entry.ServerName, finding.ServerName, StringComparison.Ordinal))
            {
                continue;
            }
            if (entry.ToolName is not null &&
                !string.Equals(entry.ToolName, finding.ToolName ?? string.Empty, StringComparison.Ordinal))
            {
                continue;
            }
            if (entry.SkillName is not null &&
                !string.Equals(entry.SkillName, finding.ServerName, StringComparison.Ordinal))
            {
                continue;
            }
            if (entry.Path is not null && finding.SkillFilePath is not null &&
                !finding.SkillFilePath.Contains(entry.Path, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (entry.Evidence is not null && finding.Evidence is not null &&
                !finding.Evidence.Contains(entry.Evidence, StringComparison.Ordinal))
            {
                continue;
            }
            if (entry.Environment is not null &&
                !string.Equals(entry.Environment, environment, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return entry;
        }
        return null;
    }
}
