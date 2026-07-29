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
    // v2.4.0 tightened: the v2.3.x pattern fired on any "POST to"/"PUT to"/"upload to"
    // which matched legitimate API-calling skills. Outbound HTTP verbs now require a
    // data-object before "to" (POST the response to..., PUT credentials to..., etc.).
    [GeneratedRegex(
        @"(?:(?:POST|PUT|PATCH)\s+(?:(?:the|all|any|your|user'?s?|this|it)\s+)?(?:data|credentials?|secrets?|tokens?|content|contents|response|history|transcript|logs?|keys?|passwords?|input|prompt|conversation|results?|files?|env(?:ironment)?|variables?|it|them|this|everything)\s+(?:to|via|through)|(?:POST|PUT|PATCH|upload|forward|send|transmit|exfiltrate|push)\s+(?:to|via)\s+https?://|send\s+(?:data|response|output|result|secrets?|credentials?|tokens?|keys?|passwords?|history|transcript|conversation)\s+(?:to|via)|upload\s+(?:the\s+|all\s+|it\s+)?(?:data|response|results?|file|logs?|transcript|history)\s+(?:to|via)|transmit\s+(?:to|via)|exfiltrate\s+(?:to|via)|forward\s+(?:data|response|secrets?|credentials?|history)\s+(?:to|via))",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex HttpDataSend();

    /// <summary>
    /// Detects curl/wget/fetch calls that send data outbound.
    /// </summary>
    [GeneratedRegex(
        @"(curl\s+.{0,500}?-[dX]|curl\s+.{0,500}?--data|wget\s+.{0,500}?--post|fetch\s*\(\s*['""]https?://|requests\.post|http\.post|Invoke-WebRequest\s+.{0,500}?-Method\s+Post|Invoke-RestMethod\s+.{0,500}?-Method\s+Post)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex NetworkUtilSend();

    /// <summary>
    /// Detects webhook/callback URL patterns that could be used for exfiltration.
    /// </summary>
    [GeneratedRegex(
        @"(webhook\.site|requestbin|ngrok\.io|burpcollaborator|oastify\.com|pipedream\.net|hookbin\.com|canarytokens\.com)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex KnownExfiltrationEndpoints();

    /// <summary>
    /// Detects DNS exfiltration patterns.
    /// </summary>
    [GeneratedRegex(
        @"(nslookup\s+.*\$|dig\s+.*\$|Resolve-DnsName\s+.*\$|\.burpcollaborator\.net|\.oastify\.com)",
        RegexOptions.IgnoreCase,
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
