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
    // v3.0.1 (F4): every verb alternative now starts with \b. Without it, "PUT" matched
    // inside "input" and "output", so ordinary prose such as
    // "Failed to copy input file to output location" graded Critical EXFIL-001 on a
    // real skill's error string.
    [GeneratedRegex(
        @"(?:\b(?:POST|PUT|PATCH)\s+(?:(?:the|all|any|your|user'?s?|this|it)\s+)?(?:data|credentials?|secrets?|tokens?|content|contents|response|history|transcript|logs?|keys?|passwords?|input|prompt|conversation|results?|files?|env(?:ironment)?|variables?|it|them|this|everything)\s+(?:to|via|through)|\b(?:POST|PUT|PATCH|upload|forward|send|transmit|exfiltrate|push)\s+(?:to|via)\s+https?://|\bsend\s+(?:data|response|output|result|secrets?|credentials?|tokens?|keys?|passwords?|history|transcript|conversation)\s+(?:to|via)|\bupload\s+(?:the\s+|all\s+|it\s+)?(?:data|response|results?|file|logs?|transcript|history)\s+(?:to|via)|\btransmit\s+(?:to|via)|\bexfiltrate\s+(?:to|via)|\bforward\s+(?:data|response|secrets?|credentials?|history)\s+(?:to|via))",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex HttpDataSend();

    /// <summary>
    /// Detects curl/wget/requests/PowerShell calls that send data outbound.
    /// </summary>
    // v3.0.0 (WP12): the JS `fetch(...)` alternative moved to its own pattern
    // (HttpFetchSend / EXFIL-005) so skill scanning can apply it only inside
    // js/ts fenced code blocks - fetch( in prose documentation is the canonical
    // way to describe an API call and was a steady false-positive source.
    [GeneratedRegex(
        @"(curl\s+.{0,500}?-[dX]|curl\s+.{0,500}?--data|wget\s+.{0,500}?--post|requests\.post|http\.post|Invoke-WebRequest\s+.{0,500}?-Method\s+Post|Invoke-RestMethod\s+.{0,500}?-Method\s+Post)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex NetworkUtilSend();

    /// <summary>
    /// Detects a JavaScript/TypeScript <c>fetch('https://...')</c> call. v3.0.0 (WP12):
    /// split out of <see cref="NetworkUtilSend"/> so callers can scope it to js/ts
    /// code segments (see docs/keyword-rules.md).
    /// </summary>
    [GeneratedRegex(
        @"fetch\s*\(\s*['""]https?://",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex HttpFetchSend();

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
            "Detected use of network utilities (curl, wget, requests, Invoke-WebRequest) to send data externally"),
        ("EXFIL-003", "Known Exfiltration Endpoint", KnownExfiltrationEndpoints(), Models.Severity.Critical,
            "Detected reference to known data exfiltration/interception service"),
        ("EXFIL-004", "DNS Exfiltration", DnsExfiltration(), Models.Severity.High,
            "Detected potential DNS-based data exfiltration pattern"),
        ("EXFIL-005", "JavaScript fetch() to External Endpoint", HttpFetchSend(), Models.Severity.Critical,
            "Detected a fetch() call to an external endpoint. For skill documents this pattern " +
            "is only evaluated inside js/ts fenced code blocks (v3.0.0, WP12)")
    ];
}
