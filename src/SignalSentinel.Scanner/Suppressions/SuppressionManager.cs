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
    /// v2.4.0 (N4): identifies suppressions that matched no finding in the current
    /// scan, or whose <see cref="SuppressionEntry.ExpiresOn"/> is in the past.
    /// These entries represent accepted risk that can no longer apply to any real
    /// finding and should be removed so the suppression list doesn't decay into a
    /// dumping ground.
    /// </summary>
    /// <param name="file">Loaded suppression file, or null.</param>
    /// <param name="findings">Findings from the current scan - typically the raw
    /// list BEFORE <see cref="Apply"/> is called, or the post-apply list (either
    /// is accepted; the algorithm inspects each entry's matchability).</param>
    /// <param name="environment">Current scan environment (matches the entry's
    /// <see cref="SuppressionEntry.Environment"/> filter when present).</param>
    /// <param name="now">Current time used for expiry evaluation. Pass
    /// <see cref="DateTimeOffset.UtcNow"/> in production.</param>
    /// <returns>Zero or more stale-entry reports, one per stale entry.</returns>
    public static IReadOnlyList<StaleSuppression> DetectStale(
        SuppressionFile? file,
        IReadOnlyList<Finding> findings,
        string environment,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentException.ThrowIfNullOrWhiteSpace(environment);

        if (file is null || file.Suppressions.Count == 0)
        {
            return [];
        }

        var results = new List<StaleSuppression>();
        for (var index = 0; index < file.Suppressions.Count; index++)
        {
            var entry = file.Suppressions[index];

            // Expiry check first - expired entries are stale regardless of whether
            // they currently match a finding.
            if (entry.ExpiresOn is not null && entry.ExpiresOn.Value < now)
            {
                results.Add(new StaleSuppression
                {
                    Entry = entry,
                    Index = index,
                    Reason = StaleSuppressionReason.Expired,
                });
                continue;
            }

            // Environment mismatch is not "stale" - the entry just doesn't apply in
            // this environment and may very well be needed in another. Skip.
            if (entry.Environment is not null &&
                !string.Equals(entry.Environment, environment, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Otherwise "stale" means: no current finding would ever be matched by
            // this entry. Run the regular match loop once per finding and ask
            // whether THIS entry (not just any entry) would hit.
            var anyMatch = false;
            foreach (var finding in findings)
            {
                if (EntryMatches(entry, finding, environment))
                {
                    anyMatch = true;
                    break;
                }
            }
            if (!anyMatch)
            {
                results.Add(new StaleSuppression
                {
                    Entry = entry,
                    Index = index,
                    Reason = StaleSuppressionReason.NoMatch,
                });
            }
        }

        return results;
    }

    private static bool EntryMatches(SuppressionEntry entry, Finding finding, string environment)
    {
        if (!string.Equals(entry.RuleId, finding.RuleId, StringComparison.Ordinal))
        {
            return false;
        }
        if (entry.ServerName is not null &&
            !string.Equals(entry.ServerName, finding.ServerName, StringComparison.Ordinal))
        {
            return false;
        }
        if (entry.ToolName is not null &&
            !string.Equals(entry.ToolName, finding.ToolName ?? string.Empty, StringComparison.Ordinal))
        {
            return false;
        }
        // v2.4.1 (G11): see the matching comment in FindMatch for rationale.
        if (entry.SkillName is not null &&
            !string.Equals(entry.SkillName, finding.CanonicalSkillName ?? finding.ServerName, StringComparison.Ordinal))
        {
            return false;
        }
        if (entry.Path is not null && finding.SkillFilePath is not null &&
            !finding.SkillFilePath.Contains(entry.Path, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        if (entry.Evidence is not null && finding.Evidence is not null &&
            !finding.Evidence.Contains(entry.Evidence, StringComparison.Ordinal))
        {
            return false;
        }
        if (entry.Environment is not null &&
            !string.Equals(entry.Environment, environment, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        return true;
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
            // v2.4.1 (G11): match against CanonicalSkillName when available so
            // suppression entries can't silently stop matching because a skill's
            // frontmatter name and directory name diverged. Comparison stays
            // case-sensitive (Ordinal) to preserve pre-v2.4.1 matching semantics -
            // only the compared field changed, not the comparison rules.
            if (entry.SkillName is not null &&
                !string.Equals(entry.SkillName, finding.CanonicalSkillName ?? finding.ServerName, StringComparison.Ordinal))
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
