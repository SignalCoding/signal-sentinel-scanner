// -----------------------------------------------------------------------
// <copyright file="OAuthComplianceRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Network;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-020: Verifies OAuth 2.1 + PKCE compliance for remote MCP servers.
/// The MCP specification mandates OAuth 2.1 for remote server authentication.
/// Maps to OWASP ASI03 / MCP07.
/// </summary>
public sealed class OAuthComplianceRule : IRule
{
    public string Id => RuleConstants.Rules.OAuthCompliance;
    public string Name => "OAuth 2.1 Compliance Check";
    public string OwaspCode => OwaspAsiCodes.ASI03;
    public string Description =>
        "Verifies OAuth 2.1 with PKCE compliance for remote MCP servers, " +
        "as mandated by the MCP specification for HTTP-based servers.";
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

            // Only applies to HTTP/WebSocket remote servers
            if (config.Transport is not (Core.McpProtocol.McpTransportType.Http
                or Core.McpProtocol.McpTransportType.StreamableHttp
                or Core.McpProtocol.McpTransportType.WebSocket))
            {
                continue;
            }

            // Check if URL uses TLS. v2.4.0 A1: exempt non-public targets. Such a
            // target is either already on an encrypted SSH tunnel (loopback) or on
            // a deliberately non-routable network; a plain http:// URL there is
            // expected, not a finding. The parallel NonPublicTargetRule emits an
            // informational SS-INFO-002 so the operator is still told that this
            // scan did not evaluate production posture.
            if (config.Url is not null)
            {
                var uri = new Uri(config.Url);
                if (uri.Scheme is "http" or "ws")
                {
                    var classification = NonPublicTarget.Classify(uri);
                    if (!NonPublicTarget.IsNonPublic(classification))
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = Severity.Critical,
                            Title = "Insecure Transport: No TLS",
                            Description = $"Remote MCP server '{server.ServerName}' uses unencrypted " +
                                $"{uri.Scheme}:// transport. The MCP specification requires TLS.",
                            Remediation = $"Use {(uri.Scheme == "ws" ? "wss" : "https")}:// for remote MCP connections.",
                            ServerName = server.ServerName,
                            Evidence = $"scheme: {uri.Scheme}",
                            Confidence = 1.0,
                            McpCode = OwaspMcpCodes.MCP09
                        });
                    }
                }
            }

            // Check if server uses basic auth pattern (static credentials)
            if (config.Env is not null)
            {
                var hasStaticAuth = config.Env.Keys.Any(k =>
                {
                    var upper = k.ToUpperInvariant();
                    return upper.Contains("BEARER", StringComparison.Ordinal) ||
                           upper.Contains("AUTHORIZATION", StringComparison.Ordinal) ||
                           upper.Contains("API_KEY", StringComparison.Ordinal) ||
                           upper.Contains("APIKEY", StringComparison.Ordinal);
                });

                if (hasStaticAuth)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Static Authentication for Remote MCP Server",
                        Description = $"Remote server '{server.ServerName}' uses static API key or " +
                            "bearer token authentication instead of OAuth 2.1 as mandated by MCP spec.",
                        Remediation = "Implement OAuth 2.1 with PKCE for remote MCP server authentication. " +
                            "See MCP specification Section 5.1 (Authorization).",
                        ServerName = server.ServerName,
                        Confidence = 0.85,
                        McpCode = OwaspMcpCodes.MCP07
                    });
                }
            }

            // v2.4.0 A2: the "no visible auth" finding is now raised by
            // MissingAuthProbeRule, which behaviourally tests whether the server
            // enforces authentication instead of introspecting the operator's
            // config file. That gives correct results when the operator uses
            // `headers: { Authorization: Bearer ... }` (new v2.3.1 config shape)
            // without rewriting the Env block - the previous heuristic produced
            // false positives in that case.

            // v2.5.0 (G13b): the MCP 2026-07-28 specification hardened the OAuth
            // authorization flow - RFC 9207 issuer validation, and Client ID
            // Metadata Documents (CIMD) replacing Dynamic Client Registration
            // (DCR). Signal Sentinel's auth probe only observes whether the
            // server enforces Bearer auth at all; it does not perform an OAuth
            // metadata discovery round-trip, so it cannot tell CIMD from DCR or
            // verify issuer validation. Disclose that scope gap explicitly
            // rather than silently passing servers that may not have adopted
            // the new hardening yet.
            if (server.AuthProbe is { AuthEnforced: true })
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Info,
                    Title = "MCP Authorization Hardening Not Verified (2026-07-28 spec)",
                    Description = $"Remote server '{server.ServerName}' enforces Bearer " +
                        "authentication, which this scanner confirmed behaviourally. It does " +
                        "not verify the MCP 2026-07-28 authorization hardening changes: RFC " +
                        "9207 issuer validation, or whether the server has moved from Dynamic " +
                        "Client Registration (DCR, now deprecated) to Client ID Metadata " +
                        "Documents (CIMD). Those checks require an OAuth metadata " +
                        "discovery round-trip this scanner does not perform.",
                    Remediation = "Manually verify (or ask the server operator to confirm) that " +
                        "the authorization server validates the `iss` parameter per RFC 9207 " +
                        "and has migrated from DCR to CIMD, per the MCP 2026-07-28 " +
                        "specification's authorization section.",
                    ServerName = server.ServerName,
                    Confidence = 0.6,
                    McpCode = OwaspMcpCodes.MCP07
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
