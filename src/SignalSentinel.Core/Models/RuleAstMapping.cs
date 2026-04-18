// -----------------------------------------------------------------------
// <copyright file="RuleAstMapping.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Core.Models;

/// <summary>
/// Canonical mapping of Signal Sentinel rule identifiers (SS-001..SS-025, SS-INFO-001)
/// to OWASP Agentic Skills Top 10 codes. Published alongside the release; see
/// <c>docs/owasp-ast-mapping.md</c>. Updated in v2.3.0 (schema version 1.0).
/// </summary>
public static class RuleAstMapping
{
    private static readonly IReadOnlyDictionary<string, string[]> Mapping =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            // MCP rules (SS-001 to SS-010)
            ["SS-001"] = [OwaspAstCodes.AST01, OwaspAstCodes.AST04],
            ["SS-002"] = [OwaspAstCodes.AST03],
            ["SS-003"] = [OwaspAstCodes.AST06],
            ["SS-004"] = [OwaspAstCodes.AST02],
            ["SS-005"] = [OwaspAstCodes.AST01, OwaspAstCodes.AST05],
            ["SS-006"] = [OwaspAstCodes.AST06],
            ["SS-007"] = [OwaspAstCodes.AST01],
            ["SS-008"] = [OwaspAstCodes.AST04],
            ["SS-009"] = [OwaspAstCodes.AST04],
            ["SS-010"] = [OwaspAstCodes.AST01, OwaspAstCodes.AST03],

            // Skill rules (SS-011 to SS-018)
            ["SS-011"] = [OwaspAstCodes.AST01, OwaspAstCodes.AST04],
            ["SS-012"] = [OwaspAstCodes.AST03],
            ["SS-013"] = [OwaspAstCodes.AST01],
            ["SS-014"] = [OwaspAstCodes.AST01, OwaspAstCodes.AST03],
            ["SS-015"] = [OwaspAstCodes.AST04],
            ["SS-016"] = [OwaspAstCodes.AST01, OwaspAstCodes.AST05],
            ["SS-017"] = [OwaspAstCodes.AST03],
            ["SS-018"] = [OwaspAstCodes.AST04],

            // v2.1.0+ MCP rules (SS-019 to SS-021)
            ["SS-019"] = [OwaspAstCodes.AST01, OwaspAstCodes.AST04],
            ["SS-020"] = [OwaspAstCodes.AST06],
            ["SS-021"] = [OwaspAstCodes.AST02, OwaspAstCodes.AST07],

            // v2.2.0 rules (SS-022 to SS-025)
            ["SS-022"] = [OwaspAstCodes.AST01, OwaspAstCodes.AST02],
            ["SS-023"] = [OwaspAstCodes.AST01],
            ["SS-024"] = [OwaspAstCodes.AST02, OwaspAstCodes.AST07],
            ["SS-025"] = [OwaspAstCodes.AST03],

            // v2.3.0 informational
            ["SS-INFO-001"] = [OwaspAstCodes.AST08]
        };

    /// <summary>
    /// Returns the AST codes mapped for a rule identifier. Returns an empty array when
    /// the rule has no mapping declared (e.g. Sigma rules or custom user rules).
    /// </summary>
    public static IReadOnlyList<string> GetCodes(string ruleId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        return Mapping.TryGetValue(ruleId, out var codes) ? codes : [];
    }

    /// <summary>
    /// Gets every rule id that has a mapping registered.
    /// </summary>
    public static IReadOnlyCollection<string> MappedRuleIds => Mapping.Keys.ToList();
}
