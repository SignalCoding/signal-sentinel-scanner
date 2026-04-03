using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-003: Detects MCP servers with missing or weak authentication.
/// OWASP ASI03: Identity &amp; Privilege Abuse
/// </summary>
public sealed class MissingAuthRule : IRule
{
    public string Id => "SS-003";
    public string Name => "Missing Authentication Detection";
    public string OwaspCode => OwaspAsiCodes.ASI03;
    public string Description => "Detects MCP servers that may be exposed without proper authentication controls.";
    public bool EnabledByDefault => true;

    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            // Check for HTTP transport without apparent auth
            if (server.ServerConfig.Transport == Core.McpProtocol.McpTransportType.Http ||
                server.ServerConfig.Transport == Core.McpProtocol.McpTransportType.StreamableHttp)
            {
                var url = server.ServerConfig.Url ?? string.Empty;

                // Check for localhost (lower risk)
                var isLocalhost = url.Contains("localhost", StringComparison.OrdinalIgnoreCase) ||
                                  url.Contains("127.0.0.1") ||
                                  url.Contains("[::1]");

                // Check for missing HTTPS
                if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !isLocalhost)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Critical,
                        Title = "Unencrypted HTTP Connection",
                        Description = $"MCP server '{server.ServerName}' is configured with unencrypted HTTP. All traffic including tool calls and responses can be intercepted.",
                        Remediation = "Configure the MCP server to use HTTPS with a valid TLS certificate. Never expose MCP servers over unencrypted HTTP.",
                        ServerName = server.ServerName,
                        Evidence = url,
                        Confidence = 1.0
                    });
                }

                // Check environment variables for API keys
                var hasApiKey = server.ServerConfig.Env?.Keys
                    .Any(k => k.Contains("key", StringComparison.OrdinalIgnoreCase) ||
                              k.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                              k.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
                              k.Contains("secret", StringComparison.OrdinalIgnoreCase)) ?? false;

                if (!hasApiKey && !isLocalhost)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "No Authentication Configured",
                        Description = $"MCP server '{server.ServerName}' appears to have no authentication configured (no API key, token, or auth environment variables found).",
                        Remediation = "Configure authentication for the MCP server using OAuth 2.1, API keys, or other appropriate authentication mechanism. Set credentials via environment variables.",
                        ServerName = server.ServerName,
                        Confidence = 0.8
                    });
                }

                // Check for public cloud endpoints
                var publicEndpoints = new[] { ".azurewebsites.net", ".amazonaws.com", ".googleapis.com", ".oraclecloud.com", ".cloudflare.com" };
                if (publicEndpoints.Any(e => url.Contains(e, StringComparison.OrdinalIgnoreCase)))
                {
                    if (!hasApiKey)
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = Severity.Critical,
                            Title = "Public Cloud Endpoint Without Auth",
                            Description = $"MCP server '{server.ServerName}' is hosted on a public cloud endpoint without apparent authentication. This server may be accessible to anyone on the internet.",
                            Remediation = "Implement authentication immediately. Use cloud-native identity (Entra ID, IAM, Google IAM) or API key authentication. Consider adding IP restrictions.",
                            ServerName = server.ServerName,
                            Evidence = url,
                            Confidence = 0.9
                        });
                    }
                }
            }

            // Check for stdio transport security
            if (server.ServerConfig.Transport == Core.McpProtocol.McpTransportType.Stdio)
            {
                var command = server.ServerConfig.Command ?? string.Empty;

                // Check for npx/npm without version pinning
                if (command.Contains("npx", StringComparison.OrdinalIgnoreCase))
                {
                    var args = string.Join(" ", server.ServerConfig.Args ?? []);
                    if (!args.Contains("@") || !args.Contains("."))
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspAsiCodes.ASI04,
                            Severity = Severity.Medium,
                            Title = "Unpinned Package Version",
                            Description = $"MCP server '{server.ServerName}' uses npx without pinning a specific package version. This could allow supply chain attacks if the latest version is compromised.",
                            Remediation = "Pin the package to a specific version (e.g., 'package@1.2.3') to prevent automatic updates to potentially compromised versions.",
                            ServerName = server.ServerName,
                            Evidence = $"{command} {args}",
                            Confidence = 0.75
                        });
                    }
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
