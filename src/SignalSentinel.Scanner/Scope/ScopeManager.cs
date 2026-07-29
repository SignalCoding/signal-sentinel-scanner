// -----------------------------------------------------------------------
// <copyright file="ScopeManager.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Scope;

/// <summary>
/// Loads <c>.sentinel-scope.json</c> and applies it to findings. Out-of-scope
/// findings are tagged <c>Scope = "dormant"</c> and retained (not dropped).
/// v2.4.0 (G7).
/// </summary>
public static class ScopeManager
{
    /// <summary>Tag applied to findings that are out of scope.</summary>
    public const string DormantTag = "dormant";

    /// <summary>Tag applied to findings that are in scope. Default state.</summary>
    public const string InScopeTag = "in-scope";

    private const long MaxFileSizeBytes = 1 * 1024 * 1024; // 1 MB

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Loads a scope file. Returns null when the file does not exist; throws
    /// <see cref="InvalidOperationException"/> on malformed content.
    /// </summary>
    public static async Task<SentinelScopeFile?> LoadAsync(
        string path, CancellationToken cancellationToken = default)
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
                $"Scope file exceeds maximum size ({MaxFileSizeBytes / 1024} KB): {info.Name}");
        }

        await using var stream = File.OpenRead(path);
        try
        {
            var file = await JsonSerializer.DeserializeAsync<SentinelScopeFile>(
                stream, JsonOptions, cancellationToken)
                ?? throw new InvalidOperationException("Scope file parsed to null");

            if (!string.Equals(file.Version, "1.0", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Unsupported scope-file schema version '{file.Version}'. Expected '1.0'.");
            }

            return file;
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Scope file is malformed JSON: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Builds a scope file from raw CLI-supplied inclusion / exclusion lists. Returns
    /// null when no filters were provided.
    /// </summary>
    public static SentinelScopeFile? FromCliFlags(
        IReadOnlyList<string>? includeSkills,
        IReadOnlyList<string>? excludeSkills,
        IReadOnlyList<string>? includeServers,
        IReadOnlyList<string>? excludeServers)
    {
        var hasSkillFilter = HasAny(includeSkills) || HasAny(excludeSkills);
        var hasServerFilter = HasAny(includeServers) || HasAny(excludeServers);
        if (!hasSkillFilter && !hasServerFilter)
        {
            return null;
        }

        return new SentinelScopeFile
        {
            Version = "1.0",
            Source = "cli",
            Skills = hasSkillFilter
                ? new ScopeSelector { Include = includeSkills, Exclude = excludeSkills }
                : null,
            Servers = hasServerFilter
                ? new ScopeSelector { Include = includeServers, Exclude = excludeServers }
                : null,
        };
    }

    /// <summary>
    /// Merges a file-sourced scope with CLI overrides. CLI wins for any filter it
    /// explicitly sets; unset filters fall back to the file.
    /// </summary>
    public static SentinelScopeFile? Merge(SentinelScopeFile? fileScope, SentinelScopeFile? cliScope)
    {
        if (fileScope is null)
        {
            return cliScope;
        }
        if (cliScope is null)
        {
            return fileScope;
        }

        return fileScope with
        {
            Source = $"{fileScope.Source ?? "file"}+cli",
            Skills = cliScope.Skills ?? fileScope.Skills,
            Servers = cliScope.Servers ?? fileScope.Servers,
        };
    }

    /// <summary>
    /// Applies scope to a list of findings. In-scope findings are tagged
    /// <see cref="InScopeTag"/>; out-of-scope findings are tagged
    /// <see cref="DormantTag"/>. Findings are never dropped.
    /// </summary>
    public static IReadOnlyList<Finding> Apply(
        IReadOnlyList<Finding> findings,
        SentinelScopeFile? scope)
    {
        ArgumentNullException.ThrowIfNull(findings);
        if (scope is null || (scope.Skills is null && scope.Servers is null))
        {
            return findings;
        }

        var result = new List<Finding>(findings.Count);
        foreach (var finding in findings)
        {
            var tag = InScopeTag;
            if (finding.Source == FindingSource.Skill)
            {
                // v2.4.1 (G11): match against CanonicalSkillName when available so
                // scope selectors agree with the suppression manager about which
                // skill a finding belongs to.
                if (scope.Skills is not null &&
                    !Matches(scope.Skills, finding.CanonicalSkillName ?? finding.ServerName))
                {
                    tag = DormantTag;
                }
            }
            else
            {
                if (scope.Servers is not null &&
                    !Matches(scope.Servers, finding.ServerName))
                {
                    tag = DormantTag;
                }
            }

            result.Add(finding with { Scope = tag });
        }
        return result;
    }

    /// <summary>
    /// True when <paramref name="name"/> is in scope per the include/exclude lists.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item>Include empty + exclude empty = everyone is in scope.</item>
    /// <item>Include non-empty: must appear on include AND not on exclude.</item>
    /// <item>Include empty + exclude non-empty: must not appear on exclude.</item>
    /// </list>
    /// Matching is ordinal case-insensitive.
    /// </remarks>
    public static bool Matches(ScopeSelector selector, string name)
    {
        ArgumentNullException.ThrowIfNull(selector);
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        if (HasAny(selector.Exclude) &&
            selector.Exclude!.Any(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }
        if (HasAny(selector.Include))
        {
            return selector.Include!
                .Any(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
        }
        return true;
    }

    private static bool HasAny(IReadOnlyList<string>? list) => list is { Count: > 0 };
}
