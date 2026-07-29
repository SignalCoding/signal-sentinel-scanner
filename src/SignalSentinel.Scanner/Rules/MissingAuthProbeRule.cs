// -----------------------------------------------------------------------
// <copyright file="MissingAuthProbeRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Network;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-020 (v2.4.0 A2): behavioural auth-posture rule. Consumes the unauthenticated
/// probe result captured during enumeration and decides whether to fire based on
/// observed server behaviour, not operator config shape.
/// </summary>
/// <remarks>
/// Replaces the v2.3.x "Env block has no auth-related key" heuristic, which
/// produced false positives when the operator authenticated via the v2.3.1
/// <c>headers: { Authorization: Bearer ... }</c> config field rather than an
/// env var. The probe-based rule asks the server directly whether it wants
/// credentials and records the evidence in the finding payload for triage.
/// </remarks>
public sealed class MissingAuthProbeRule : IRule
{
    public string Id => RuleConstants.Rules.OAuthCompliance;
    public string Name => "OAuth 2.1 Compliance Check (auth probe)";
    public string OwaspCode => OwaspAsiCodes.ASI03;
    public string Description =>
        "Sends a deliberate unauthenticated MCP initialize request to remote " +
        "servers and fires when the server does not demand authentication. " +
        "v2.4.0 replacement for the previous config-shape heuristic.";
    public bool EnabledByDefault => true;

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var config = server.ServerConfig;
            if (config.Transport is not (Core.McpProtocol.McpTransportType.Http
                or Core.McpProtocol.McpTransportType.StreamableHttp
                or Core.McpProtocol.McpTransportType.WebSocket))
            {
                continue;
            }

            // Non-public targets are exempted: SS-INFO-002 is the operator-facing
            // notification for those and transport-posture rules deliberately
            // don't apply. Keeps the rule aligned with A1.
            if (config.Url is not null &&
                Uri.TryCreate(config.Url, UriKind.Absolute, out var uri))
            {
                var classification = NonPublicTarget.Classify(uri);
                if (NonPublicTarget.IsNonPublic(classification))
                {
                    continue;
                }
            }

            var probe = server.AuthProbe;
            if (probe is null)
            {
                // No probe was sent (stdio transport, non-public, unreachable).
                // Nothing behavioural to evaluate.
                continue;
            }

            // Server enforced auth → good posture, no finding.
            if (probe.AuthEnforced)
            {
                continue;
            }

            // Server accepted an anonymous MCP initialize → open; Medium finding
            // with the status code and optional WWW-Authenticate string as evidence.
            if (probe.AnonymousInitializeSucceeded)
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = "Server Accepted Unauthenticated MCP Initialize",
                    Description =
                        $"Remote server '{server.ServerName}' accepted an MCP " +
                        $"`initialize` request with no `Authorization` header and " +
                        $"no WWW-Authenticate challenge (probe returned HTTP " +
                        $"{probe.StatusCode}). The MCP specification requires " +
                        "OAuth 2.1 for remote servers.",
                    Remediation =
                        "Configure the server to require OAuth 2.1 Bearer tokens " +
                        "(or equivalent authentication) on all MCP endpoints. " +
                        "Return HTTP 401 with a `WWW-Authenticate: Bearer " +
                        "realm=\"mcp\", resource_metadata=\"...\"` header per " +
                        "RFC 9728 §5 for unauthenticated requests.",
                    ServerName = server.ServerName,
                    Evidence = $"probe: status={probe.StatusCode} classification={probe.Classification}",
                    Confidence = 0.95,
                    McpCode = OwaspMcpCodes.MCP07,
                });
                continue;
            }

            // v2.4.1 (G2): StatusCode 0 means the HTTP request never completed at all
            // (connection refused, DNS failure, timeout - see AuthProbeService's catch
            // block). That is a connectivity failure, not an auth-posture observation;
            // emitting "Auth Posture Unclear" here would misrepresent a network problem
            // as a security finding about the server's auth configuration.
            if (probe.StatusCode == 0)
            {
                continue;
            }

            // "unclear": 4xx without a Bearer challenge or 5xx. Low severity because
            // the scanner can't be confident about the auth posture - the server
            // might be broken, might be hiding behind a proxy, or might refuse
            // anonymous calls without signalling how to authenticate.
            if (string.Equals(probe.Classification, "unclear", StringComparison.Ordinal))
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Low,
                    Title = "Auth Posture Unclear",
                    Description =
                        $"Unauthenticated probe of '{server.ServerName}' returned " +
                        $"HTTP {probe.StatusCode}" +
                        (probe.Note is not null ? $" ({probe.Note})" : ".") +
                        " The server did not issue a Bearer challenge, so the scanner " +
                        "cannot confirm whether authentication is enforced.",
                    Remediation =
                        "Ensure unauthenticated MCP requests return HTTP 401 with a " +
                        "`WWW-Authenticate: Bearer ...` header so MCP clients can " +
                        "discover the auth posture.",
                    ServerName = server.ServerName,
                    Evidence = $"probe: status={probe.StatusCode} classification=unclear",
                    Confidence = 0.6,
                    McpCode = OwaspMcpCodes.MCP07,
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
