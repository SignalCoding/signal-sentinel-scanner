// -----------------------------------------------------------------------
// <copyright file="ExfiltrationPatterns.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;

namespace SignalSentinel.Core.Security;

/// <summary>
/// Regex patterns for detecting data exfiltration attempts.
/// Shared between MCP tool scanning and Agent Skill scanning.
/// Aligned with OWASP ASI09 (Sensitive Data Leakage).
/// </summary>
public static partial class ExfiltrationPatterns
{
    /// <summary>
    /// Detects HTTP POST/PUT/PATCH to external endpoints.
    /// </summary>
    [GeneratedRegex(
        @"(POST\s+to|PUT\s+to|PATCH\s+to|send\s+(data|response|output|result)\s+to|upload\s+to|transmit\s+to|exfiltrate\s+to|forward\s+(data|response)\s+to)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex HttpDataSend();

    /// <summary>
    /// Detects curl/wget/fetch calls that send data outbound.
    /// </summary>
    [GeneratedRegex(
        @"(curl\s+.*-[dX]|curl\s+.*--data|wget\s+.*--post|fetch\s*\(\s*['""]https?://|requests\.post|http\.post|Invoke-WebRequest\s+.*-Method\s+Post|Invoke-RestMethod\s+.*-Method\s+Post)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex NetworkUtilSend();

    /// <summary>
    /// Detects webhook/callback URL patterns that could be used for exfiltration.
    /// </summary>
    [GeneratedRegex(
        @"(webhook\.site|requestbin|ngrok\.io|burpcollaborator|oastify\.com|pipedream\.net|hookbin\.com|canarytokens\.com)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex KnownExfiltrationEndpoints();

    /// <summary>
    /// Detects DNS exfiltration patterns.
    /// </summary>
    [GeneratedRegex(
        @"(nslookup\s+.*\$|dig\s+.*\$|Resolve-DnsName\s+.*\$|\.burpcollaborator\.net|\.oastify\.com)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex DnsExfiltration();

    /// <summary>
    /// All exfiltration detection patterns with metadata.
    /// </summary>
    public static IReadOnlyList<(string Id, string Name, Regex Pattern, Models.Severity Severity, string Description)> AllPatterns { get; } =
    [
        ("EXFIL-001", "HTTP Data Exfiltration", HttpDataSend(), Models.Severity.Critical,
            "Detected instructions to send data to external endpoints via HTTP"),
        ("EXFIL-002", "Network Utility Exfiltration", NetworkUtilSend(), Models.Severity.Critical,
            "Detected use of network utilities (curl, wget, fetch) to send data externally"),
        ("EXFIL-003", "Known Exfiltration Endpoint", KnownExfiltrationEndpoints(), Models.Severity.Critical,
            "Detected reference to known data exfiltration/interception service"),
        ("EXFIL-004", "DNS Exfiltration", DnsExfiltration(), Models.Severity.High,
            "Detected potential DNS-based data exfiltration pattern")
    ];
}
