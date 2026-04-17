// -----------------------------------------------------------------------
// <copyright file="ExcessiveResponseRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-025: Flags tools whose schema complexity or description length
/// suggests the tool may return excessively large or deeply-nested responses.
/// Maps to OWASP ASI06 (Memory/Context Poisoning) and MCP05 (Insecure Data Handling).
/// </summary>
/// <remarks>
/// v2.2.0 implements this as a static analysis rule evaluating description size
/// and parameter-schema nesting depth. Live response-size sampling requires
/// an opt-in tool invocation path and is deferred.
/// </remarks>
public sealed class ExcessiveResponseRule : IRule
{
    private const int HighDescriptionLengthThreshold = 10_000;
    private const int CriticalDescriptionLengthThreshold = 50_000;
    private const int MaxRecommendedNestingDepth = 10;

    /// <inheritdoc />
    public string Id => RuleConstants.Rules.ExcessiveToolResponse;

    /// <inheritdoc />
    public string Name => "Excessive Tool Response Size";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI06;

    /// <inheritdoc />
    public string Description =>
        "Flags tools with unusually large descriptions or deeply-nested parameter schemas that may produce memory-poisoning responses.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            foreach (var tool in server.Tools)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var descriptionLength = tool.Description?.Length ?? 0;
                if (descriptionLength >= CriticalDescriptionLengthThreshold)
                {
                    findings.Add(CreateDescriptionFinding(server.ServerName, tool.Name, descriptionLength, Severity.High));
                }
                else if (descriptionLength >= HighDescriptionLengthThreshold)
                {
                    findings.Add(CreateDescriptionFinding(server.ServerName, tool.Name, descriptionLength, Severity.Medium));
                }

                if (tool.InputSchema is { } schema)
                {
                    var depth = MeasureDepth(schema, 0);
                    if (depth > MaxRecommendedNestingDepth)
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            McpCode = "MCP05",
                            Severity = Severity.Medium,
                            Title = $"Deeply-Nested Tool Schema: {tool.Name}",
                            Description =
                                $"Tool '{tool.Name}' on server '{server.ServerName}' declares a parameter schema with nesting depth {depth} " +
                                $"(recommended maximum: {MaxRecommendedNestingDepth}). Deep schemas increase the risk of memory poisoning and parser-exhaustion attacks.",
                            Remediation =
                                "Flatten the parameter schema or split the tool into smaller, single-purpose tools.",
                            ServerName = server.ServerName,
                            ToolName = tool.Name,
                            Evidence = $"nesting depth = {depth}",
                            Confidence = 1.0
                        });
                    }
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private Finding CreateDescriptionFinding(string serverName, string toolName, int length, Severity severity)
    {
        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            McpCode = "MCP05",
            Severity = severity,
            Title = $"Excessive Tool Description Size: {toolName}",
            Description =
                $"Tool '{toolName}' on server '{serverName}' declares a description of {length:N0} characters. " +
                "Very large descriptions can poison agent memory and may be used to hide malicious payloads among legitimate content.",
            Remediation =
                "Shorten the tool description to a concise summary. Move detailed documentation to external references.",
            ServerName = serverName,
            ToolName = toolName,
            Evidence = $"description length = {length:N0}",
            Confidence = 1.0
        };
    }

    private static int MeasureDepth(JsonElement element, int current)
    {
        if (current > 64)
        {
            // Safety net: arbitrary ceiling prevents malicious schemas from causing stack overflow
            return current;
        }

        return element.ValueKind switch
        {
            JsonValueKind.Object => element.EnumerateObject().Select(p => MeasureDepth(p.Value, current + 1)).DefaultIfEmpty(current + 1).Max(),
            JsonValueKind.Array => element.EnumerateArray().Select(e => MeasureDepth(e, current + 1)).DefaultIfEmpty(current + 1).Max(),
            _ => current
        };
    }
}
