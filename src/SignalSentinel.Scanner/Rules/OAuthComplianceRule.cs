// -----------------------------------------------------------------------
// <copyright file="OAuthComplianceRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;

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

            // Check if URL uses TLS
            if (config.Url is not null)
            {
                var uri = new Uri(config.Url);
                if (uri.Scheme is "http" or "ws")
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

            // Remote server with no visible auth configuration
            if (config.Env is null || config.Env.Count == 0)
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = "No Authentication Configuration for Remote Server",
                    Description = $"Remote server '{server.ServerName}' has no visible authentication " +
                        "configuration. The MCP specification requires OAuth 2.1 for remote servers.",
                    Remediation = "Configure OAuth 2.1 with PKCE authentication for this remote MCP server. " +
                        "If the server uses anonymous access, document the security justification.",
                    ServerName = server.ServerName,
                    Confidence = 0.7,
                    McpCode = OwaspMcpCodes.MCP07
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
