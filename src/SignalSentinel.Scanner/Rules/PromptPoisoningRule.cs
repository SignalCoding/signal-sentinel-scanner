// -----------------------------------------------------------------------
// <copyright file="PromptPoisoningRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-030: Detects prompt-injection patterns in MCP <c>prompts/list</c> metadata
/// (prompt descriptions and argument descriptions). Maps to OWASP ASI01.
/// </summary>
/// <remarks>
/// Prompts are rendered directly into the conversation when the user selects them,
/// and clients commonly surface the description and argument hints verbatim. The
/// same pattern set that catches tool poisoning (SS-001) applies here; the finding
/// is separated so operators can tell which primitive carried the payload.
/// </remarks>
public sealed class PromptPoisoningRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.PromptPoisoning;

    /// <inheritdoc />
    public string Name => "MCP Prompt Poisoning";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description =>
        "Detects prompt injection and hidden-instruction patterns in MCP prompt " +
        "descriptions and prompt argument descriptions.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST04];

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            foreach (var prompt in server.Prompts)
            {
                cancellationToken.ThrowIfCancellationRequested();

                foreach (var (pattern, evidence) in DescriptionScan.Matches(prompt.Description))
                {
                    findings.Add(Create(server.ServerName, prompt.Name, "description", pattern, evidence));
                }

                if (prompt.Arguments is null)
                {
                    continue;
                }

                foreach (var argument in prompt.Arguments)
                {
                    foreach (var (pattern, evidence) in DescriptionScan.Matches(argument.Description))
                    {
                        findings.Add(Create(server.ServerName, prompt.Name, $"argument '{argument.Name}'", pattern, evidence));
                    }
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private Finding Create(
        string serverName,
        string promptName,
        string field,
        Core.Security.InjectionPattern pattern,
        string evidence)
    {
        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = pattern.Severity,
            Title = $"Prompt Poisoning: {pattern.Name}",
            Description = $"{pattern.Description}. Pattern '{pattern.Id}' matched in the {field} of prompt '{promptName}'.",
            Remediation =
                "Prompt descriptions and argument hints must describe, not instruct. Remove " +
                "directive language, references to other tools or external URLs, encoded " +
                "payloads, and hidden characters.",
            ServerName = serverName,
            ToolName = promptName,
            Evidence = evidence,
            Confidence = 0.9,
            McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
        };
    }
}
