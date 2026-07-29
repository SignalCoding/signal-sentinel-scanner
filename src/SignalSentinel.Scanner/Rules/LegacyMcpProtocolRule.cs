// -----------------------------------------------------------------------
// <copyright file="LegacyMcpProtocolRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-INFO-004 (v2.5.0, G13a): informational rule that flags MCP servers still
/// operating on a protocol version or transport that the MCP <c>2026-07-28</c>
/// specification has put on a deprecation clock. That release retired the
/// <c>initialize</c>/<c>initialized</c> handshake and <c>Mcp-Session-Id</c> session
/// header in favour of a stateless protocol core, and formally deprecated the
/// legacy HTTP+SSE transport - both with a 12-month backward-compatibility
/// window. Servers on the old scheme still work today; this finding is an
/// early-warning currency notice, not a vulnerability.
/// Maps to OWASP AST08 (Poor Scanning) in the same informational sense as
/// SS-INFO-001/SS-INFO-003: an opaque "it connected fine" result would
/// otherwise hide a signal the scanner did observe.
/// </summary>
public sealed class LegacyMcpProtocolRule : IRule
{
    public string Id => RuleConstants.Rules.LegacyMcpProtocol;
    public string Name => "Legacy MCP Protocol / Transport";
    public string OwaspCode => OwaspAsiCodes.ASI04;
    public string Description =>
        "Flags MCP servers negotiating a protocol version older than the current " +
        "MCP specification, or reached over the deprecated legacy HTTP+SSE " +
        "transport, so operators can track migration before the 12-month " +
        "backward-compatibility window closes.";
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

            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            var usesLegacyTransport = string.Equals(
                server.Transport, nameof(McpTransportType.Http), StringComparison.Ordinal);
            var negotiatedLegacyVersion = server.ProtocolVersion is { Length: > 0 } version &&
                string.CompareOrdinal(version, McpProtocolVersions.Current) < 0;

            if (!usesLegacyTransport && !negotiatedLegacyVersion)
            {
                continue;
            }

            var notes = new List<string>();
            if (negotiatedLegacyVersion)
            {
                notes.Add($"negotiated protocol version '{server.ProtocolVersion}' predates " +
                    $"the current '{McpProtocolVersions.Current}' specification");
            }
            if (usesLegacyTransport)
            {
                notes.Add("uses the legacy HTTP+SSE transport, deprecated in favour of Streamable HTTP");
            }

            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                AstCodes = AstCodes,
                Severity = Severity.Info,
                Title = $"Legacy MCP Protocol/Transport ({server.ServerName})",
                Description = $"Server '{server.ServerName}' {string.Join(" and ", notes)}. " +
                    "The MCP 2026-07-28 specification retired the initialize/initialized " +
                    "handshake and Mcp-Session-Id header in favour of a stateless protocol " +
                    "core, and formally deprecated the legacy HTTP+SSE transport. Both keep " +
                    "working for at least 12 months from release, but new servers should not " +
                    "be built against them.",
                Remediation = "Plan migration to the MCP 2026-07-28 specification: upgrade the " +
                    "server's MCP SDK, move off HTTP+SSE to Streamable HTTP if applicable, and " +
                    "verify the deployment before the 12-month deprecation window closes.",
                ServerName = server.ServerName,
                Evidence = $"transport: {server.Transport}; protocolVersion: {server.ProtocolVersion ?? "(unknown)"}",
                Confidence = 0.95,
                Source = FindingSource.Mcp
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
