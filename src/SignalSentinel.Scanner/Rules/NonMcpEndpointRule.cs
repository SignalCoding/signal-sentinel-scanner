// -----------------------------------------------------------------------
// <copyright file="NonMcpEndpointRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-INFO-001: Informational rule that surfaces a finding when the scanner detects
/// that an alleged remote MCP endpoint is in fact not an MCP server at all (for
/// example: a React SPA with catch-all routing that returns <c>text/html</c> for
/// every path). Prevents the scanner from misleadingly emitting "Grade A / 0 findings"
/// against a host that has no MCP protocol surface.
/// Maps to OWASP AST08 (Poor Scanning).
/// </summary>
public sealed class NonMcpEndpointRule : IRule
{
    public string Id => RuleConstants.Rules.NonMcpEndpoint;
    public string Name => "Non-MCP Endpoint Detected";
    public string OwaspCode => OwaspAsiCodes.ASI10;
    public string Description =>
        "Detects remote endpoints that are reachable but do not implement the MCP " +
        "protocol (e.g. a web application SPA returning HTML for every path).";
    public bool EnabledByDefault => true;
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST08];

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (server.NonMcpEvidence is null)
            {
                continue;
            }

            var evidence = server.NonMcpEvidence;
            var snippet = evidence.BodySnippet is null
                ? string.Empty
                : $" | body: {Truncate(evidence.BodySnippet, 120)}";

            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                AstCodes = AstCodes,
                Severity = Severity.Info,
                Title = $"Non-MCP Endpoint Detected ({server.ServerName})",
                Description =
                    $"The endpoint configured as MCP server '{server.ServerName}' returned a " +
                    $"response that does not look like the MCP JSON-RPC 2.0 protocol " +
                    $"(reason: {evidence.Reason}). This usually indicates the URL points at " +
                    $"a web application (SPA, documentation site, reverse proxy catch-all) " +
                    $"rather than an MCP server. Result: MCP-protocol rules (SS-001..SS-010, " +
                    $"SS-019..SS-025) cannot evaluate and were skipped for this target.",
                Remediation =
                    "Verify that this URL serves an MCP transport (HTTP/SSE, WebSocket, or " +
                    "stdio). HTML responses suggest a web application, not an MCP server. " +
                    "If this host is not an MCP server, remove it from the target list; the " +
                    "skill-surface scans (SS-011..SS-018) remain valid where applicable.",
                ServerName = server.ServerName,
                Evidence = $"content-type={evidence.ContentType ?? "(none)"}{snippet}",
                Confidence = 0.95,
                Source = FindingSource.Mcp
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..(max - 3)] + "...";
}
