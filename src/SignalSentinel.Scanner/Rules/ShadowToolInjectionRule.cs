// -----------------------------------------------------------------------
// <copyright file="ShadowToolInjectionRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-023: Detects shadow tool injection attacks where a tool name closely
/// resembles a privileged built-in or a tool on another server (typosquat).
/// Maps to OWASP ASI01 (Agent Goal Hijack) and MCP02 (Excessive Permissions).
/// </summary>
public sealed class ShadowToolInjectionRule : IRule
{
    private const int MaxEditDistance = 2;

    // High-value tool names that a typosquat would target
    private static readonly string[] PrivilegedTargets =
    [
        "read_file", "write_file", "delete_file",
        "exec", "execute", "shell",
        "admin", "root", "sudo",
        "auth", "authenticate", "login",
        "credentials", "secrets", "tokens",
        "database", "query", "sql"
    ];

    /// <inheritdoc />
    public string Id => RuleConstants.Rules.ShadowToolInjection;

    /// <inheritdoc />
    public string Name => "Shadow Tool Injection";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description =>
        "Detects tools whose names closely resemble privileged built-in operations or tools on other servers, indicating possible typosquatting.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var findings = new List<Finding>();

        // Flatten all tools for cross-server comparison
        var allTools = context.Servers
            .Where(s => s.ConnectionSuccessful)
            .SelectMany(s => s.Tools.Select(t => (Server: s.ServerName, Tool: t.Name)))
            .ToList();

        foreach (var (serverName, toolName) in allTools)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Check against privileged targets
            foreach (var target in PrivilegedTargets)
            {
                if (string.Equals(toolName, target, StringComparison.OrdinalIgnoreCase))
                {
                    continue; // Exact match: not shadowing, it IS the privileged tool
                }

                var distance = LevenshteinDistance.Compute(toolName.ToLowerInvariant(), target);
                if (distance > 0 && distance <= MaxEditDistance && toolName.Length >= 4)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        McpCode = "MCP02",
                        Severity = Severity.High,
                        Title = $"Possible Shadow Tool: '{toolName}' shadows privileged '{target}'",
                        Description =
                            $"Tool '{toolName}' on server '{serverName}' is {distance} edit(s) away from privileged operation '{target}'. " +
                            "This pattern is consistent with typosquat attacks intended to trick the agent into invoking a malicious tool.",
                        Remediation =
                            $"Rename the tool to a clearly distinct name if legitimate. If the tool is not expected to provide '{target}' functionality, investigate its source.",
                        ServerName = serverName,
                        ToolName = toolName,
                        Evidence = $"{toolName} ~ {target} (distance={distance})",
                        Confidence = distance == 1 ? 0.85 : 0.7
                    });
                    break; // One finding per tool per category
                }
            }
        }

        // Cross-server shadowing: two tools on different servers with near-identical names
        for (var i = 0; i < allTools.Count; i++)
        {
            var (serverA, toolA) = allTools[i];
            for (var j = i + 1; j < allTools.Count; j++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var (serverB, toolB) = allTools[j];

                if (string.Equals(serverA, serverB, StringComparison.Ordinal))
                {
                    continue;
                }
                if (string.Equals(toolA, toolB, StringComparison.OrdinalIgnoreCase))
                {
                    continue; // Identical tool names across servers are a different concern (SS-010)
                }
                if (toolA.Length < 4 || toolB.Length < 4)
                {
                    continue;
                }

                var distance = LevenshteinDistance.Compute(
                    toolA.ToLowerInvariant(),
                    toolB.ToLowerInvariant());

                if (distance == 1)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        McpCode = "MCP02",
                        Severity = Severity.Medium,
                        Title = $"Cross-Server Typosquat: '{toolA}' vs '{toolB}'",
                        Description =
                            $"Tool '{toolA}' on '{serverA}' is a single edit away from '{toolB}' on '{serverB}'. " +
                            "This cross-server similarity could be used to trick an agent into calling the wrong tool.",
                        Remediation =
                            "Confirm both tools are legitimate. Consider renaming one to prevent confusion.",
                        ServerName = serverA,
                        ToolName = toolA,
                        Evidence = $"{toolA} ~ {toolB} on {serverB}",
                        Confidence = 0.75
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
