// -----------------------------------------------------------------------
// <copyright file="RugPullDetectionRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-022: Detects rug-pull attacks where MCP tool schemas silently mutate between scans.
/// Maps to OWASP ASI01 (Agent Goal Hijack) and MCP01 (Tool Poisoning).
/// </summary>
/// <remarks>
/// This rule consumes the <see cref="BaselineComparison"/> produced by <c>BaselineManager</c>.
/// The rule emits no findings when no baseline is present (first scan) or when no mutations are detected.
/// </remarks>
/// <remarks>
/// Initialises a new instance of the <see cref="RugPullDetectionRule"/> class.
/// </remarks>
/// <param name="comparison">Baseline comparison produced by the scan pipeline.</param>
public sealed class RugPullDetectionRule(BaselineComparison? comparison) : IRule
{
    private readonly BaselineComparison? _comparison = comparison;

    /// <inheritdoc />
    public string Id => RuleConstants.Rules.RugPullDetection;

    /// <inheritdoc />
    public string Name => "Rug Pull Detection (Schema Mutation)";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description =>
        "Detects silent mutations of MCP tool descriptions or parameter schemas between baseline and current scan.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if (_comparison is null || !_comparison.BaselineLoaded)
        {
            return Task.FromResult<IEnumerable<Finding>>([]);
        }

        var findings = new List<Finding>();

        foreach (var mutation in _comparison.MutatedTools)
        {
            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                McpCode = "MCP01",
                Severity = Severity.Critical,
                Title = $"Tool Schema Mutation Detected: {mutation.Tool.ToolName}",
                Description =
                    $"Tool '{mutation.Tool.ToolName}' on server '{mutation.Tool.ServerName}' has mutated since baseline. " +
                    $"{mutation.Summary} This is consistent with a rug-pull attack where a trusted MCP server silently modifies tool behaviour post-approval.",
                Remediation =
                    "Review the tool changes carefully. If the mutation is expected, regenerate the baseline with --update-baseline. " +
                    "If unexpected, disconnect the MCP server immediately and investigate.",
                ServerName = mutation.Tool.ServerName,
                ToolName = mutation.Tool.ToolName,
                Evidence = mutation.Type.ToString(),
                Confidence = 1.0
            });
        }

        foreach (var added in _comparison.AddedTools)
        {
            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                McpCode = "MCP01",
                Severity = Severity.High,
                Title = $"New Tool Added: {added.ToolName}",
                Description =
                    $"Tool '{added.ToolName}' on server '{added.ServerName}' did not exist in the baseline. " +
                    "Silent tool additions post-approval can indicate a rug-pull attack.",
                Remediation =
                    "Review the new tool definition. If intended, regenerate the baseline with --update-baseline. Otherwise, investigate.",
                ServerName = added.ServerName,
                ToolName = added.ToolName,
                Evidence = "Tool added since baseline",
                Confidence = 0.9
            });
        }

        foreach (var removed in _comparison.RemovedTools)
        {
            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                McpCode = "MCP01",
                Severity = Severity.Medium,
                Title = $"Tool Removed: {removed.ToolName}",
                Description =
                    $"Tool '{removed.ToolName}' on server '{removed.ServerName}' was present in the baseline but is missing now. " +
                    "Silent tool removal may indicate attacker replacement or deprecation that has not been reviewed.",
                Remediation =
                    "Confirm the removal was intended. If so, regenerate the baseline with --update-baseline.",
                ServerName = removed.ServerName,
                ToolName = removed.ToolName,
                Evidence = "Tool removed since baseline",
                Confidence = 0.9
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
