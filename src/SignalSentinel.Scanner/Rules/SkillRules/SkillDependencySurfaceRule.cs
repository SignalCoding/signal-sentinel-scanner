// -----------------------------------------------------------------------
// <copyright file="SkillDependencySurfaceRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Osv;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// v3.0.0 (WP6): SS-INFO-006. Lists the package dependencies found in scanned skills
/// when they were NOT checked against OSV — because --osv was absent, the scan is
/// offline, or the lookup failed — so the operator knows exactly what went unverified.
/// Silent when the lookup succeeded or no dependencies exist.
/// </summary>
public sealed class SkillDependencySurfaceRule : IRule
{
    private const int MaxListedPackages = 25;

    public string Id => RuleConstants.Rules.SkillDependencySurface;

    public string Name => "Skill Dependency Surface (Unchecked)";

    public string OwaspCode => "ASI04";

    public string Description =>
        "Lists package dependencies found in scanned skills that were not checked against " +
        "the OSV vulnerability database (--osv absent, offline scan, or failed lookup).";

    public bool EnabledByDefault => true;

    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST02];

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if (context.DependencySurface is not { } surface
            || surface.Dependencies.Count == 0
            || surface.Status == DependencyQueryStatus.Succeeded)
        {
            return Task.FromResult(Enumerable.Empty<Finding>());
        }

        var reason = surface.Status switch
        {
            DependencyQueryStatus.NotRequested => "the --osv flag was not given",
            DependencyQueryStatus.Offline => "the scan ran offline",
            DependencyQueryStatus.Failed => $"the OSV lookup failed ({surface.FailureReason ?? "unknown error"})",
            _ => "the lookup did not complete"
        };

        var findings = surface.Dependencies
            .GroupBy(d => d.SkillName, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var packages = g
                    .Select(d => d.Version is null ? d.Name : $"{d.Name}@{d.Version}")
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(MaxListedPackages + 1)
                    .ToList();
                var listed = string.Join(", ", packages.Take(MaxListedPackages));
                if (packages.Count > MaxListedPackages)
                {
                    listed += ", ...";
                }

                var count = g.Count();
                return new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Info,
                    Title = $"Skill Dependencies Not Checked Against OSV: {g.Key}",
                    Description = $"Skill '{g.Key}' references {count} package dependenc{(count == 1 ? "y" : "ies")} " +
                        $"({listed}) and {reason}, so known-vulnerability status is unverified.",
                    Remediation = "Re-run with --osv (network access required) to check these packages against osv.dev.",
                    ServerName = g.Key,
                    Confidence = 1.0,
                    Source = FindingSource.Skill
                };
            })
            .ToList();

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
