// -----------------------------------------------------------------------
// <copyright file="ObfuscationPatterns.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;

namespace SignalSentinel.Core.Security;

/// <summary>
/// Regex patterns for detecting obfuscation and evasion techniques.
/// Shared between MCP tool scanning and Agent Skill scanning.
/// Aligned with OWASP ASI01 (Agent Goal Hijack).
/// </summary>
public static partial class ObfuscationPatterns
{
    /// <summary>
    /// Detects zero-width characters used to hide content.
    /// </summary>
    [GeneratedRegex(
        @"[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u034F\u180E]{2,}",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex ZeroWidthCharClusters();

    /// <summary>
    /// Detects Unicode bidirectional override characters used for visual spoofing.
    /// </summary>
    [GeneratedRegex(
        @"[\u202A-\u202E\u2066-\u2069]",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex BidiOverrides();

    /// <summary>
    /// Detects base64-encoded command strings (common in script payloads).
    /// </summary>
    [GeneratedRegex(
        @"(base64\s*[\-]?[dD]|atob\s*\(|Buffer\.from\s*\(.+,\s*['""]base64['""]|b64decode|base64\.b64decode|FromBase64String|\.decode\s*\(\s*['""]base64['""])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex Base64Decoding();

    /// <summary>
    /// Detects eval/exec calls that execute dynamically constructed strings.
    /// </summary>
    [GeneratedRegex(
        @"(\beval\s*\(|\bexec\s*\(|Function\s*\(|Invoke-Expression|iex\s+|new\s+Function\s*\(|compile\s*\(.+exec\s*\()",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex DynamicExecution();

    /// <summary>
    /// Detects character code assembly (constructing strings from char codes to evade detection).
    /// </summary>
    [GeneratedRegex(
        @"(String\.fromCharCode|chr\s*\(\s*\d+|\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}|charCodeAt|ord\s*\()",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex CharCodeAssembly();

    /// <summary>
    /// Detects string reversal tricks used to hide command strings.
    /// </summary>
    [GeneratedRegex(
        @"(\.reverse\s*\(\s*\)\.join|reversed\s*\(|strrev\s*\(|\[::-1\]|-join\s+.*\[.+\.\.\s*0\])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex StringReversal();

    /// <summary>
    /// All obfuscation detection patterns with metadata.
    /// </summary>
    public static IReadOnlyList<(string Id, string Name, Regex Pattern, Models.Severity Severity, string Description)> AllPatterns { get; } =
    [
        ("OBFUSC-001", "Zero-Width Character Clusters", ZeroWidthCharClusters(), Models.Severity.High,
            "Detected clusters of zero-width characters that may hide malicious content"),
        ("OBFUSC-002", "Bidirectional Override", BidiOverrides(), Models.Severity.High,
            "Detected Unicode bidirectional override characters used for visual spoofing"),
        ("OBFUSC-003", "Base64 Decoding", Base64Decoding(), Models.Severity.Medium,
            "Detected base64 decoding operation that may conceal malicious payload"),
        ("OBFUSC-004", "Dynamic Execution", DynamicExecution(), Models.Severity.High,
            "Detected dynamic code execution (eval/exec) that can run arbitrary code"),
        ("OBFUSC-005", "Character Code Assembly", CharCodeAssembly(), Models.Severity.Medium,
            "Detected character code assembly pattern used to construct hidden strings"),
        ("OBFUSC-006", "String Reversal", StringReversal(), Models.Severity.Medium,
            "Detected string reversal technique used to obfuscate command strings")
    ];
}
