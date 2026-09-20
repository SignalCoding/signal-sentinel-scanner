// -----------------------------------------------------------------------
// <copyright file="OsvLookup.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.SkillParser;

namespace SignalSentinel.Scanner.Osv;

/// <summary>
/// v3.0.0 (WP6): builds the <see cref="DependencySurface"/> for a scan. Extraction is
/// always performed (it is local and free); the network lookup runs only with
/// <c>--osv</c> and never under <c>--offline</c>. Any failure degrades to a Failed
/// surface, surfaced as SS-INFO-006 — never to a scan error.
/// </summary>
public static class OsvLookup
{
    /// <summary>
    /// Extracts dependencies from every skill and, when requested, queries OSV for the
    /// pinned subset (deduplicated, capped at <see cref="OsvClient.MaxPackagesPerRun"/>).
    /// </summary>
    public static Task<DependencySurface> BuildAsync(
        IReadOnlyList<SkillDefinition> skills,
        bool osvRequested,
        bool offline,
        CancellationToken cancellationToken = default) =>
        BuildAsync(skills, osvRequested, offline, queryOverride: null, cancellationToken);

    /// <summary>
    /// Core implementation; tests inject <paramref name="queryOverride"/> to avoid the
    /// network. Production passes null and gets <see cref="OsvClient.CreateDefault"/>.
    /// </summary>
    internal static async Task<DependencySurface> BuildAsync(
        IReadOnlyList<SkillDefinition> skills,
        bool osvRequested,
        bool offline,
        Func<IReadOnlyList<SkillDependency>, CancellationToken, Task<IReadOnlyList<OsvVulnerability>>>? queryOverride,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(skills);

        var dependencies = skills
            .SelectMany(DependencyExtractor.Extract)
            .GroupBy(d => (d.SkillName, d.Name, d.Version, d.Ecosystem), DependencyKeyComparer.Instance)
            .Select(g => g.First())
            .ToList();

        if (!osvRequested)
        {
            return new DependencySurface
            {
                Dependencies = dependencies,
                Status = DependencyQueryStatus.NotRequested
            };
        }

        if (offline)
        {
            return new DependencySurface
            {
                Dependencies = dependencies,
                Status = DependencyQueryStatus.Offline
            };
        }

        var pinned = dependencies.Where(d => d.Version is not null).ToList();
        var queried = pinned.Take(OsvClient.MaxPackagesPerRun).ToList();

        if (queried.Count == 0)
        {
            return new DependencySurface
            {
                Dependencies = dependencies,
                Status = DependencyQueryStatus.Succeeded,
                QueriedCount = 0,
                Truncated = false
            };
        }

        try
        {
            var vulnerabilities = queryOverride is not null
                ? await queryOverride(queried, cancellationToken).ConfigureAwait(false)
                : await OsvClient.CreateDefault().QueryAsync(queried, cancellationToken).ConfigureAwait(false);

            return new DependencySurface
            {
                Dependencies = dependencies,
                Status = DependencyQueryStatus.Succeeded,
                Vulnerabilities = vulnerabilities,
                QueriedCount = queried.Count,
                Truncated = pinned.Count > queried.Count
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new DependencySurface
            {
                Dependencies = dependencies,
                Status = DependencyQueryStatus.Failed,
                FailureReason = ex.GetType().Name,
                QueriedCount = 0,
                Truncated = pinned.Count > OsvClient.MaxPackagesPerRun
            };
        }
    }

    private sealed class DependencyKeyComparer : IEqualityComparer<(string Skill, string Name, string? Version, string Ecosystem)>
    {
        public static readonly DependencyKeyComparer Instance = new();

        public bool Equals(
            (string Skill, string Name, string? Version, string Ecosystem) x,
            (string Skill, string Name, string? Version, string Ecosystem) y) =>
            string.Equals(x.Skill, y.Skill, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Name, y.Name, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Version, y.Version, StringComparison.Ordinal)
            && string.Equals(x.Ecosystem, y.Ecosystem, StringComparison.Ordinal);

        public int GetHashCode((string Skill, string Name, string? Version, string Ecosystem) obj) =>
            HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Skill),
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Name),
                obj.Version is null ? 0 : StringComparer.Ordinal.GetHashCode(obj.Version),
                StringComparer.Ordinal.GetHashCode(obj.Ecosystem));
    }
}
