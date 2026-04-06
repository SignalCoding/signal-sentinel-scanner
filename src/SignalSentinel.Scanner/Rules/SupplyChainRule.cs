using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-004: Detects supply chain vulnerabilities including typosquatting and version drift.
/// OWASP ASI04: Supply Chain Vulnerabilities
/// </summary>
public sealed partial class SupplyChainRule : IRule
{
    public string Id => RuleConstants.Rules.SupplyChain;
    public string Name => "Supply Chain Vulnerability Detection";
    public string OwaspCode => OwaspAsiCodes.ASI04;
    public string Description => "Detects potential supply chain vulnerabilities including typosquatting, version drift, and compromised packages.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(@"@([a-z0-9-]+)/", RegexOptions.None, matchTimeoutMilliseconds: 500)]
    private static partial Regex NpmScopePattern();

    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            // Check server name for typosquatting
            var typosquatResult = TyposquatDetector.CheckForTyposquat(server.ServerName);
            if (typosquatResult.IsSuspicious)
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.High,
                    Title = "Potential Typosquat Detected",
                    Description = $"Server name '{server.ServerName}' may be a typosquat of legitimate server '{typosquatResult.MatchedLegitimateServer}'. {typosquatResult.Reason}",
                    Remediation = $"Verify this is the intended server. If not, remove it and use the legitimate '{typosquatResult.MatchedLegitimateServer}' instead.",
                    ServerName = server.ServerName,
                    Evidence = $"Similarity: {typosquatResult.Similarity:P0}, Distance: {typosquatResult.Distance}",
                    Confidence = typosquatResult.Similarity ?? 0.85
                });
            }

            // Check for suspicious npm package patterns
            var command = server.ServerConfig.Command ?? string.Empty;
            var args = string.Join(" ", server.ServerConfig.Args ?? []);
            var fullCommand = $"{command} {args}".ToLowerInvariant();

            // Check for packages from unknown sources
            if (fullCommand.Contains("npx") || fullCommand.Contains("npm"))
            {
                // Check for git URLs (potentially untrusted sources)
                if (fullCommand.Contains("github.com") || fullCommand.Contains("gitlab.com") || fullCommand.Contains("git+"))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Medium,
                        Title = "Package Installed from Git URL",
                        Description = $"Server '{server.ServerName}' installs a package directly from a Git URL rather than a registry. This bypasses npm registry security checks.",
                        Remediation = "Use packages from official npm registry when possible. If using Git sources, verify the repository is legitimate and pin to a specific commit hash.",
                        ServerName = server.ServerName,
                        Evidence = fullCommand,
                        Confidence = 0.7
                    });
                }

                // Check for scoped packages that might be typosquats
                if (fullCommand.Contains("@") && !fullCommand.Contains("@anthropic/") && !fullCommand.Contains("@modelcontextprotocol/"))
                {
                    var scopeMatch = NpmScopePattern().Match(fullCommand);
                    if (scopeMatch.Success)
                    {
                        var scope = scopeMatch.Groups[1].Value;
                        var knownScopes = new[] { "anthropic", "modelcontextprotocol", "microsoft", "google", "aws", "azure" };

                        if (!knownScopes.Contains(scope))
                        {
                            findings.Add(new Finding
                            {
                                RuleId = Id,
                                OwaspCode = OwaspCode,
                                Severity = Severity.Low,
                                Title = "Unknown Package Scope",
                                Description = $"Server '{server.ServerName}' uses a package from scope '@{scope}' which is not a known official MCP provider.",
                                Remediation = "Verify the package scope is from a trusted source. Consider using official MCP packages when available.",
                                ServerName = server.ServerName,
                                Evidence = $"@{scope}",
                                Confidence = 0.5
                            });
                        }
                    }
                }
            }

            // Check for hash pinning drift (if previous scan available)
            if (context.PreviousScan is not null && server.ConnectionSuccessful)
            {
                var previousServer = context.PreviousScan.Servers
                    .FirstOrDefault(s => s.Name == server.ServerName);

                if (previousServer is not null)
                {
                    // Compare tool manifests
                    var previousToolCount = context.PreviousScan.Statistics.TotalTools;
                    var currentToolCount = server.Tools.Count;

                    if (previousToolCount > 0 && currentToolCount != previousToolCount)
                    {
                        var diff = currentToolCount - previousToolCount;
                        var severity = Math.Abs(diff) > 5 ? Severity.High : Severity.Medium;

                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = severity,
                            Title = "Tool Manifest Change Detected",
                            Description = $"Server '{server.ServerName}' has {(diff > 0 ? "added" : "removed")} {Math.Abs(diff)} tools since last scan. This could indicate a supply chain compromise or 'rug pull'.",
                            Remediation = "Review the tool changes. If unexpected, investigate the server source and consider reverting to a known-good version.",
                            ServerName = server.ServerName,
                            Evidence = $"Previous: {previousToolCount} tools, Current: {currentToolCount} tools",
                            Confidence = 0.75
                        });
                    }
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
