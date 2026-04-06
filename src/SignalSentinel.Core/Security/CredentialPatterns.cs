// -----------------------------------------------------------------------
// <copyright file="CredentialPatterns.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;

namespace SignalSentinel.Core.Security;

/// <summary>
/// Regex patterns for detecting credential access and secret exposure.
/// Shared between MCP tool scanning and Agent Skill scanning.
/// Aligned with OWASP ASI03 (Identity and Privilege Abuse).
/// </summary>
public static partial class CredentialPatterns
{
    /// <summary>
    /// Detects references to well-known API key environment variables.
    /// </summary>
    [GeneratedRegex(
        @"(\$ANTHROPIC_API_KEY|\$OPENAI_API_KEY|\$AWS_SECRET_ACCESS_KEY|\$AWS_ACCESS_KEY_ID|\$AZURE_CLIENT_SECRET|\$GCP_SERVICE_ACCOUNT_KEY|\$GITHUB_TOKEN|\$GITLAB_TOKEN|\$SLACK_TOKEN|\$DISCORD_TOKEN|\$STRIPE_SECRET_KEY|\$TWILIO_AUTH_TOKEN|\$SENDGRID_API_KEY|\$DATABASE_URL|\$DB_PASSWORD|\$REDIS_PASSWORD)",
        RegexOptions.None,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex WellKnownApiKeyVars();

    /// <summary>
    /// Detects generic environment variable credential access patterns.
    /// </summary>
    [GeneratedRegex(
        @"(\$\{?[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)[A-Z_]*\}?|process\.env\.[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z_]*|os\.environ\[.[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD))",
        RegexOptions.None,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex GenericEnvVarCredentials();

    /// <summary>
    /// Detects references to SSH key files.
    /// </summary>
    [GeneratedRegex(
        @"(~/.ssh/id_rsa|~/.ssh/id_ed25519|~/.ssh/id_ecdsa|~/.ssh/config|\.ssh/authorized_keys|\.ssh/known_hosts|id_rsa\.pub)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex SshKeyAccess();

    /// <summary>
    /// Detects references to credential/secret files.
    /// </summary>
    [GeneratedRegex(
        @"(\.env\b|\.env\.local|\.env\.production|\.aws/credentials|\.azure/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|\.netrc|\.npmrc|\.pypirc|credentials\.json|service[_-]?account[_-]?key\.json|keystore\.jks|\.p12\b|\.pfx\b|\.pem\b)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex SecretFileAccess();

    /// <summary>
    /// Detects hardcoded secret patterns (API keys, tokens, passwords in config).
    /// </summary>
    [GeneratedRegex(
        @"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20,}|xoxb-[0-9]+-[a-zA-Z0-9]+|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|sk_live_[a-zA-Z0-9]{24,})",
        RegexOptions.None,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex HardcodedSecrets();

    /// <summary>
    /// All credential detection patterns with metadata.
    /// </summary>
    public static IReadOnlyList<(string Id, string Name, Regex Pattern, Models.Severity Severity, string Description)> AllPatterns { get; } =
    [
        ("CRED-001", "Well-Known API Key Variable", WellKnownApiKeyVars(), Models.Severity.High,
            "Detected reference to a well-known API key environment variable"),
        ("CRED-002", "Generic Credential Variable", GenericEnvVarCredentials(), Models.Severity.High,
            "Detected generic environment variable credential access pattern"),
        ("CRED-003", "SSH Key Access", SshKeyAccess(), Models.Severity.Critical,
            "Detected reference to SSH key files"),
        ("CRED-004", "Secret File Access", SecretFileAccess(), Models.Severity.High,
            "Detected reference to credential or secret configuration files"),
        ("CRED-005", "Hardcoded Secret", HardcodedSecrets(), Models.Severity.Critical,
            "Detected hardcoded API key, token, or secret pattern")
    ];
}
