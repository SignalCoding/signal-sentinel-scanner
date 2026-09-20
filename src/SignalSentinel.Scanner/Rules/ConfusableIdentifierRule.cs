// -----------------------------------------------------------------------
// <copyright file="ConfusableIdentifierRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-036: Flags identifiers that use Unicode lookalikes, invisible characters, or
/// mixed scripts. Maps to OWASP ASI01 (Agent Goal Hijack).
/// </summary>
/// <remarks>
/// SS-023 catches ASCII typosquats by edit distance. This rule catches the case
/// SS-023 cannot see: two names that are byte-different but pixel-identical, such as
/// <c>read_file</c> and <c>rеad_file</c> with a Cyrillic <c>е</c>. Identifiers are
/// tool, prompt and resource names, server names, and skill names. When two
/// identifiers in the scan share a skeleton but differ as strings, every non-ASCII
/// member of the collision is High (it is shadowing the ASCII one). An identifier that
/// is suspicious on its own (invisible characters, disallowed script mixing, or a
/// whole-script homoglyph with no collision yet) is Medium.
/// </remarks>
public sealed class ConfusableIdentifierRule : IRule
{
    private const int MaxIdentifiers = 20_000;

    /// <inheritdoc />
    public string Id => RuleConstants.Rules.ConfusableIdentifier;

    /// <inheritdoc />
    public string Name => "Unicode Confusable Identifier";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description =>
        "Detects tool, prompt, resource, server and skill names that use Unicode lookalikes, invisible characters, or mixed scripts to impersonate other identifiers.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST04];

    private sealed record Identifier(string Kind, string Name, string Owner, string? SkillPath, ConfusableAnalysis Analysis);

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var identifiers = Collect(context, cancellationToken);
        var findings = new List<Finding>();
        var reported = new HashSet<(string Kind, string Name, string Owner)>();

        // Pass 1: skeleton collisions across the whole scan.
        foreach (var group in identifiers.GroupBy(i => i.Analysis.Skeleton, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var distinctNames = group.Select(i => i.Name).Distinct(StringComparer.Ordinal).ToList();
            if (distinctNames.Count < 2)
            {
                continue;
            }

            foreach (var member in group)
            {
                if (member.Analysis.IsAscii)
                {
                    // The plain-ASCII name is the impersonated party, not the impersonator.
                    continue;
                }

                var others = group
                    .Where(o => !string.Equals(o.Name, member.Name, StringComparison.Ordinal))
                    .Select(o => $"{o.Kind} '{o.Name}' ({o.Owner})")
                    .Distinct(StringComparer.Ordinal)
                    .Take(3)
                    .ToList();

                if (reported.Add((member.Kind, member.Name, member.Owner)))
                {
                    findings.Add(Create(member, Severity.High,
                        $"Confusable {member.Kind} Name Collides With Another Identifier",
                        $"{member.Kind} '{member.Name}' on '{member.Owner}' is visually identical to {string.Join(", ", others)} but differs in Unicode code points. " +
                        "An agent or reviewer reading the two names cannot tell them apart; the non-ASCII one is positioned to receive calls intended for the other.",
                        "Rename the identifier to plain ASCII. If the non-ASCII form is not yours, treat the server or skill that supplied it as hostile.",
                        $"{member.Name} => skeleton '{member.Analysis.Skeleton}'; scripts: {string.Join("+", member.Analysis.Scripts)}",
                        0.95));
                }
            }
        }

        // Pass 2: standalone suspicious identifiers.
        foreach (var identifier in identifiers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var a = identifier.Analysis;
            if (!a.IsSuspicious || reported.Contains((identifier.Kind, identifier.Name, identifier.Owner)))
            {
                continue;
            }

            string title;
            string description;
            string evidence;

            if (a.Invisibles.Count > 0)
            {
                title = $"{identifier.Kind} Name Contains Invisible Characters";
                description = $"{identifier.Kind} '{identifier.Name}' on '{identifier.Owner}' contains {a.Invisibles.Count} zero-width or bidi-control character(s). They render as nothing, so the displayed name differs from the string an agent matches on.";
                evidence = $"{identifier.Name}: {string.Join(" ", a.Invisibles.Distinct().Take(5))}";
            }
            else if (a.IsMixedScript)
            {
                title = $"{identifier.Kind} Name Mixes Scripts";
                description = $"{identifier.Kind} '{identifier.Name}' on '{identifier.Owner}' mixes {string.Join(" and ", a.Scripts)} letters. Legitimate identifiers almost never do; homoglyph attacks almost always do.";
                evidence = $"{identifier.Name} => skeleton '{a.Skeleton}'; scripts: {string.Join("+", a.Scripts)}";
            }
            else
            {
                title = $"{identifier.Kind} Name Is A Whole-Script Homoglyph";
                description = $"{identifier.Kind} '{identifier.Name}' on '{identifier.Owner}' is written entirely in non-ASCII characters that look like the ASCII name '{a.Skeleton}'. No matching ASCII identifier is present in this scan, but one may be in the agent's other servers.";
                evidence = $"{identifier.Name} => skeleton '{a.Skeleton}'; scripts: {string.Join("+", a.Scripts)}";
            }

            reported.Add((identifier.Kind, identifier.Name, identifier.Owner));
            findings.Add(Create(identifier, Severity.Medium, title, description,
                "Use plain ASCII identifiers. Remove invisible characters and do not mix scripts within one name.",
                evidence, 0.85));
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static List<Identifier> Collect(ScanContext context, CancellationToken cancellationToken)
    {
        var list = new List<Identifier>();

        void Add(string kind, string? name, string owner, string? skillPath = null)
        {
            if (string.IsNullOrWhiteSpace(name) || list.Count >= MaxIdentifiers)
            {
                return;
            }

            list.Add(new Identifier(kind, name, owner, skillPath, Confusables.Analyse(name)));
        }

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Add("Server", server.ServerName, server.ServerName);

            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            foreach (var tool in server.Tools)
            {
                Add("Tool", tool.Name, server.ServerName);
            }

            foreach (var prompt in server.Prompts)
            {
                Add("Prompt", prompt.Name, server.ServerName);
            }

            foreach (var resource in server.Resources)
            {
                Add("Resource", resource.Name, server.ServerName);
            }
        }

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Add("Skill", skill.CanonicalSkillName, skill.SourcePlatform ?? "skills", skill.FilePath);
        }

        return list;
    }

    private Finding Create(Identifier identifier, Severity severity, string title, string description, string remediation, string evidence, double confidence)
    {
        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = severity,
            Title = title,
            Description = description,
            Remediation = remediation,
            ServerName = identifier.Owner,
            ToolName = identifier.Kind == "Skill" ? null : identifier.Name,
            Evidence = DescriptionScan.Truncate(evidence),
            Confidence = confidence,
            Source = identifier.Kind == "Skill" ? FindingSource.Skill : FindingSource.Mcp,
            SkillFilePath = identifier.SkillPath,
            McpCode = identifier.Kind == "Skill" ? null : OwaspMcpCodes.GetCorrespondingMcpCode(Id)
        };
    }
}
