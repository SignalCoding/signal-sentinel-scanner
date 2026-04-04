// -----------------------------------------------------------------------
// <copyright file="CredentialHygieneRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-019: Checks for credential hygiene issues in MCP server configurations.
/// Detects static API keys, long-lived PATs, env var credential passing without vault.
/// Maps to OWASP ASI03 (Identity and Privilege Abuse) / MCP07 (Authentication Gaps).
/// </summary>
public sealed class CredentialHygieneRule : IRule
{
    public string Id => RuleConstants.Rules.CredentialHygiene;
    public string Name => "Credential Hygiene Check";
    public string OwaspCode => OwaspAsiCodes.ASI03;
    public string Description =>
        "Detects static API keys, hardcoded secrets, and credential passing via " +
        "environment variables without vault integration in MCP configurations.";
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

            // Check environment variables for hardcoded secrets
            if (config.Env is not null)
            {
                foreach (var (key, value) in config.Env)
                {
                    // Check for hardcoded secret patterns in values
                    if (InjectionPatterns.SafeIsMatch(CredentialPatterns.HardcodedSecrets(), value))
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = Severity.Critical,
                            Title = "Hardcoded Secret in MCP Configuration",
                            Description = $"Server '{server.ServerName}' has a hardcoded secret " +
                                $"in environment variable '{key}'. This is a critical security risk.",
                            Remediation = "Use a secret manager (Azure Key Vault, AWS Secrets Manager, " +
                                "HashiCorp Vault) instead of hardcoding secrets in configuration files.",
                            ServerName = server.ServerName,
                            Evidence = $"env.{key} = [REDACTED]",
                            Confidence = 0.95,
                            McpCode = OwaspMcpCodes.MCP07
                        });
                    }

                    // Check if env var name suggests credential content
                    var keyUpper = key.ToUpperInvariant();
                    if (IsCredentialKey(keyUpper) && !string.IsNullOrEmpty(value))
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = Severity.High,
                            Title = "Credential Passed via Environment Variable",
                            Description = $"Server '{server.ServerName}' passes credential '{key}' " +
                                "via environment variable without vault integration.",
                            Remediation = "Use dynamic secret injection from a vault/secret manager " +
                                "rather than static environment variables.",
                            ServerName = server.ServerName,
                            Evidence = $"env.{key}",
                            Confidence = 0.85,
                            McpCode = OwaspMcpCodes.MCP07
                        });
                    }
                }
            }

            // Check command args for hardcoded secrets
            if (config.Args is not null)
            {
                foreach (var arg in config.Args)
                {
                    if (InjectionPatterns.SafeIsMatch(CredentialPatterns.HardcodedSecrets(), arg))
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = Severity.Critical,
                            Title = "Hardcoded Secret in Command Arguments",
                            Description = $"Server '{server.ServerName}' has a hardcoded secret " +
                                "in its command arguments.",
                            Remediation = "Move secrets to environment variables or a secret manager. " +
                                "Never pass secrets as command-line arguments.",
                            ServerName = server.ServerName,
                            Evidence = "[REDACTED command argument]",
                            Confidence = 0.95,
                            McpCode = OwaspMcpCodes.MCP07
                        });
                    }
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static bool IsCredentialKey(string key) =>
        key.Contains("KEY", StringComparison.Ordinal) ||
        key.Contains("SECRET", StringComparison.Ordinal) ||
        key.Contains("TOKEN", StringComparison.Ordinal) ||
        key.Contains("PASSWORD", StringComparison.Ordinal) ||
        key.Contains("CREDENTIAL", StringComparison.Ordinal) ||
        key.Contains("AUTH", StringComparison.Ordinal) ||
        key.Contains("PAT", StringComparison.Ordinal) && key.Length <= 10;
}
