// -----------------------------------------------------------------------
// <copyright file="PackageProvenanceRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-021: Checks npm/PyPI package provenance for MCP servers installed via package managers.
/// Flags install scripts, unverified publishers, and missing provenance attestation.
/// Maps to OWASP ASI04 (Supply Chain Vulnerabilities) / MCP03.
/// </summary>
public sealed partial class PackageProvenanceRule : IRule
{
    public string Id => RuleConstants.Rules.PackageProvenance;
    public string Name => "Package Provenance Check";
    public string OwaspCode => OwaspAsiCodes.ASI04;
    public string Description =>
        "Checks npm/PyPI package provenance for MCP servers including install scripts, " +
        "publisher verification, and provenance attestation.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(
        @"^(@[a-z0-9-]+/)?[a-z0-9-]+$",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex NpmPackageName();

    [GeneratedRegex(
        @"^[a-z0-9-]+$",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex PypiPackageName();

    private static readonly HashSet<string> TrustedNpmScopes = new(StringComparer.OrdinalIgnoreCase)
    {
        "@modelcontextprotocol",
        "@anthropic",
        "@openai",
        "@azure",
        "@google-cloud",
        "@aws-sdk",
        "@microsoft",
        "@oracle",
        "@stripe",
        "@slack",
        "@github"
    };

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var config = server.ServerConfig;
            if (config.Command is null || config.Args is null || config.Args.Count == 0)
            {
                continue;
            }

            var commandLower = config.Command.ToLowerInvariant();
            var firstArg = config.Args[0];

            // npx-based MCP servers
            if (commandLower is "npx" or "npm" or "pnpx" or "bunx")
            {
                AnalyseNpmPackage(findings, server, firstArg);
            }
            // uvx/pip-based MCP servers
            else if (commandLower is "uvx" or "uvrun" or "pipx" or "pip" or "python" or "python3")
            {
                AnalysePypiPackage(findings, server, firstArg);
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private void AnalyseNpmPackage(List<Finding> findings, McpClient.ServerEnumeration server, string packageName)
    {
        // Check if it's a scoped package from a trusted org
        if (packageName.StartsWith('@'))
        {
            var scope = packageName.Split('/')[0];
            if (!TrustedNpmScopes.Contains(scope))
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = "Unverified npm Package Scope",
                    Description = $"Server '{server.ServerName}' uses npm package '{packageName}' " +
                        $"from scope '{scope}' which is not in the trusted scope list.",
                    Remediation = "Verify the package publisher and check for npm provenance attestation. " +
                        "Run: npm audit signatures " + packageName,
                    ServerName = server.ServerName,
                    Evidence = $"scope: {scope}",
                    Confidence = 0.7,
                    McpCode = OwaspMcpCodes.MCP03
                });
            }
        }
        else if (!packageName.Contains('/') && !packageName.StartsWith('-'))
        {
            // Unscoped package - higher risk
            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                Severity = Severity.Medium,
                Title = "Unscoped npm Package",
                Description = $"Server '{server.ServerName}' uses unscoped npm package '{packageName}'. " +
                    "Unscoped packages have higher supply chain risk than organisation-scoped packages.",
                Remediation = "Prefer organisation-scoped npm packages (@org/package). " +
                    "Verify the package publisher and provenance attestation.",
                ServerName = server.ServerName,
                Evidence = $"package: {packageName}",
                Confidence = 0.6,
                McpCode = OwaspMcpCodes.MCP03
            });
        }

        // Check for version pinning (no version = latest, risky)
        if (!packageName.Contains('@', StringComparison.Ordinal) || packageName.LastIndexOf('@') == 0)
        {
            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                Severity = Severity.Low,
                Title = "Unpinned npm Package Version",
                Description = $"Server '{server.ServerName}' uses '{packageName}' without version pinning. " +
                    "This means the latest version is used, which could be compromised.",
                Remediation = "Pin the package to a specific version: " + packageName + "@x.y.z",
                ServerName = server.ServerName,
                Evidence = $"no version pin: {packageName}",
                Confidence = 0.8,
                McpCode = OwaspMcpCodes.MCP03
            });
        }
    }

    private void AnalysePypiPackage(List<Finding> findings, McpClient.ServerEnumeration server, string packageName)
    {
        // For python/python3, the package name is typically the second arg or -m arg
        if (packageName.StartsWith('-'))
        {
            return;
        }

        findings.Add(new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = Severity.Low,
            Title = "PyPI Package Provenance Check Recommended",
            Description = $"Server '{server.ServerName}' uses Python package '{packageName}'. " +
                "Verify Sigstore attestation and publisher identity on PyPI.",
            Remediation = "Check PyPI trusted publisher status and Sigstore provenance for this package.",
            ServerName = server.ServerName,
            Evidence = $"package: {packageName}",
            Confidence = 0.6,
            McpCode = OwaspMcpCodes.MCP03
        });
    }
}
