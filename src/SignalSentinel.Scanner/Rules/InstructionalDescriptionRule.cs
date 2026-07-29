// -----------------------------------------------------------------------
// <copyright file="InstructionalDescriptionRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-026: Instructional Tool Description.
/// </summary>
/// <remarks>
/// Flags MCP tool descriptions that try to drive the agent's behaviour instead of
/// describing what the tool does. Canonical examples are descriptions that start
/// with "You must call this tool first…", "Before using any other tool, always…",
/// or that wrap what should be a one-line summary in instructions aimed at the
/// model. These patterns are both a clean signature of tool-poisoning attempts
/// and a skill-authoring anti-pattern that tends to lead to prompt injection in
/// downstream agents.
/// <para>
/// v2.4.0 (N5). Medium severity; confidence is moderate because a false-positive
/// rate is expected on tools whose descriptions legitimately contain verbs like
/// "must" or "always" (e.g. safety wording). Deduplicated into one finding per
/// tool.
/// </para>
/// <para>
/// v2.4.1 (G6): also evaluates skill frontmatter <c>description:</c> fields and
/// <c>SKILL.md</c> body text for the same phrase set. SS-011 (Skill Instruction
/// Injection) overlaps partially but uses coarser patterns aimed at active
/// injection rather than this rule's narrower "instructs the agent instead of
/// describing the capability" signature; both may legitimately fire on the same
/// skill.
/// </para>
/// </remarks>
public sealed partial class InstructionalDescriptionRule : IRule
{
    public string Id => RuleConstants.Rules.InstructionalToolDescription;
    public string Name => "Instructional Tool/Skill Description";
    public string OwaspCode => OwaspAsiCodes.ASI01;
    public string Description =>
        "Flags MCP tool descriptions and skill frontmatter/body text that attempt " +
        "to instruct the agent (\"you must call this first\", \"before using any " +
        "other tool\") rather than describing what the tool or skill does. These " +
        "are both tool-poisoning signatures and skill-authoring anti-patterns.";
    public bool EnabledByDefault => true;
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST04];

    // Imperatives aimed at the agent: "you must", "always call", "before using any"...
    [GeneratedRegex(
        @"\b(you\s+must|you\s+should\s+always|you\s+are\s+required\s+to" +
        @"|always\s+(call|invoke|use)\s+this" +
        @"|before\s+(using|calling)\s+(any\s+other|another)\s+tool" +
        @"|call\s+this\s+tool\s+first" +
        @"|ignore\s+(all\s+)?previous\s+(instructions|messages)" +
        @"|this\s+tool\s+must\s+be\s+called\s+before" +
        @"|regardless\s+of\s+the\s+user" +
        @")",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex InstructionalPattern();

    // Descriptions that point the agent at other tools as a composition order.
    [GeneratedRegex(
        @"\b(after\s+calling\s+this,\s+(also\s+)?(call|invoke)" +
        @"|then\s+invoke\s+the\s+\w+\s+tool" +
        @"|chain\s+this\s+with\s+the\s+\w+\s+tool" +
        @")",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex CompositionPattern();

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            foreach (var tool in server.Tools)
            {
                var description = tool.Description ?? string.Empty;
                if (description.Length == 0)
                {
                    continue;
                }

                string? evidence = null;
                if (InstructionalPattern().Match(description) is { Success: true } im)
                {
                    evidence = im.Value;
                }
                else if (CompositionPattern().Match(description) is { Success: true } cm)
                {
                    evidence = cm.Value;
                }

                if (evidence is null)
                {
                    continue;
                }

                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = $"Instructional description on tool '{tool.Name}'",
                    Description =
                        $"Tool '{tool.Name}' has a description that instructs the " +
                        "agent rather than describing the tool. This is both a " +
                        "tool-poisoning signature and a skill-authoring anti-pattern; " +
                        "tool descriptions should state capabilities, inputs, and " +
                        "side effects, not prescribe agent behaviour.",
                    Remediation =
                        "Rewrite the tool description to state what the tool returns " +
                        "and under what conditions. Remove imperatives addressed to " +
                        "the agent (\"you must\", \"always call\", \"before any other tool\"). " +
                        "Drive orchestration decisions from an explicit policy or agent " +
                        "prompt that the operator controls.",
                    ServerName = server.ServerName,
                    Evidence = evidence,
                    Confidence = 0.7,
                    McpCode = OwaspMcpCodes.MCP01,
                });
            }
        }

        // v2.4.1 (G6): skills have analogous frontmatter description: fields and
        // SKILL.md body text but were previously invisible to this rule. One finding
        // per skill (description checked first, body second) to match the
        // "one finding per surface" pattern used for tools above.
        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var description = skill.Description ?? string.Empty;
            var body = skill.InstructionsBody ?? string.Empty;

            string? evidence = MatchEvidence(description) ?? MatchEvidence(body);
            if (evidence is null)
            {
                continue;
            }

            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                AstCodes = AstCodes,
                Severity = Severity.Medium,
                Title = $"Instructional description on skill '{skill.Name}'",
                Description =
                    $"Skill '{skill.Name}' has a description or body that instructs " +
                    "the agent rather than describing the skill's purpose. This is " +
                    "both a tool-poisoning-style signature and a skill-authoring " +
                    "anti-pattern; skill descriptions should state what the skill " +
                    "does, not prescribe agent behaviour.",
                Remediation =
                    "Rewrite the skill's frontmatter description and opening body " +
                    "text to state its purpose and scope. Remove imperatives " +
                    "addressed to the agent (\"you must\", \"always call\", " +
                    "\"before any other tool\").",
                ServerName = skill.Name,
                Evidence = evidence,
                Confidence = 0.7,
                Source = FindingSource.Skill,
                SkillFilePath = skill.FilePath
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static string? MatchEvidence(string text)
    {
        if (text.Length == 0)
        {
            return null;
        }

        if (InstructionalPattern().Match(text) is { Success: true } im)
        {
            return im.Value;
        }
        if (CompositionPattern().Match(text) is { Success: true } cm)
        {
            return cm.Value;
        }
        return null;
    }
}
