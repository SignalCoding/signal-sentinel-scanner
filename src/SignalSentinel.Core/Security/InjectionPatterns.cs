using System.Text.RegularExpressions;

namespace SignalSentinel.Core.Security;

/// <summary>
/// Regex patterns for detecting prompt injection and tool poisoning attempts.
/// Aligned with OWASP ASI01 (Agent Goal Hijack) detection requirements.
/// Security hardened with regex timeouts to prevent ReDoS attacks.
/// </summary>
public static partial class InjectionPatterns
{
    /// <summary>
    /// Safely matches a pattern with timeout protection.
    /// </summary>
    public static bool SafeIsMatch(Regex pattern, string? input)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        if (string.IsNullOrEmpty(input))
        {
            return false;
        }

        try
        {
            // Security: Truncate very long inputs to prevent DoS
            if (input.Length > 100_000)
            {
                input = input[..100_000];
            }

            return pattern.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            // Security: Treat timeouts as no match (safe default)
            return false;
        }
    }

    /// <summary>
    /// Safely finds all matches with timeout protection.
    /// </summary>
    public static IEnumerable<Match> SafeMatches(Regex pattern, string? input)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        if (string.IsNullOrEmpty(input))
        {
            yield break;
        }

        // Security: Truncate very long inputs
        if (input.Length > 100_000)
        {
            input = input[..100_000];
        }

        MatchCollection? matches;
        try
        {
            matches = pattern.Matches(input);
        }
        catch (RegexMatchTimeoutException)
        {
            yield break;
        }

        // Security: Limit number of matches returned
        var count = 0;
        foreach (Match match in matches)
        {
            if (++count > 100)
            {
                break;
            }
            yield return match;
        }
    }

    /// <summary>
    /// Pattern 1: Instruction injection keywords.
    /// Detects attempts to inject instructions via IMPORTANT, ALWAYS, MUST, NEVER, IGNORE.
    /// </summary>
    [GeneratedRegex(
        @"\b(IMPORTANT|ALWAYS|MUST|NEVER|IGNORE\s*PREVIOUS|DISREGARD|OVERRIDE|SYSTEM\s*PROMPT|YOU\s*ARE\s*NOW)\b[:\s]",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex InstructionInjection();

    /// <summary>
    /// Pattern 2: Data exfiltration indicators.
    /// Detects references to external URLs, HTTP methods, or network utilities.
    /// </summary>
    [GeneratedRegex(
        @"(https?://|fetch\s*\(|curl\s+|wget\s+|POST\s+to|send\s+to\s+|exfiltrate|transmit\s+to)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex DataExfiltration();

    /// <summary>
    /// Pattern 3: Sensitive file system access.
    /// Detects references to sensitive files, paths, or environment variables.
    /// </summary>
    [GeneratedRegex(
        @"(/etc/passwd|/etc/shadow|~/.ssh|\.env\b|\.aws/credentials|api[_-]?key|secret[_-]?key|\.git/config|id_rsa)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex SensitiveFileAccess();

    /// <summary>
    /// Pattern 4: Cross-tool manipulation.
    /// Detects instructions to invoke other tools or chain operations.
    /// </summary>
    [GeneratedRegex(
        @"(then\s+(call|invoke|use|execute)\s+|chain\s+with|after\s+this\s*,?\s*(call|use)|pipe\s+to|forward\s+to)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex CrossToolManipulation();

    /// <summary>
    /// Pattern 5: Hidden content indicators.
    /// Detects HTML comments, zero-width characters, or Unicode direction overrides.
    /// </summary>
    [GeneratedRegex(
        @"(<!--.*?-->|\u200B|\u200C|\u200D|\u2060|\uFEFF|[\u202A-\u202E]|\u0000)",
        RegexOptions.None,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex HiddenContent();

    /// <summary>
    /// Pattern 6: Base64 encoded content (potential payloads).
    /// </summary>
    [GeneratedRegex(
        @"[A-Za-z0-9+/]{50,}={0,2}",
        RegexOptions.None,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex Base64Payload();

    /// <summary>
    /// Pattern 7: Privilege escalation.
    /// Detects instructions involving sudo, admin, root, or elevated permissions.
    /// </summary>
    [GeneratedRegex(
        @"\b(sudo|as\s+root|as\s+admin|with\s+admin|elevate|privilege|become\s+root)\b",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex PrivilegeEscalation();

    /// <summary>
    /// Pattern 8: Obfuscation techniques.
    /// Detects string concatenation, escaping, or encoding patterns.
    /// </summary>
    [GeneratedRegex(
        @"(\+\s*['""][^'""]+['""]\s*\+|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|String\.fromCharCode)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex Obfuscation();

    /// <summary>
    /// Pattern 9: Jailbreak attempts.
    /// Detects common jailbreak prompting patterns.
    /// </summary>
    [GeneratedRegex(
        @"(DAN\s*mode|jailbreak|bypass\s*(safety|filter|guard)|pretend\s+you\s+are|act\s+as\s+if|roleplay\s+as)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex JailbreakAttempt();

    /// <summary>
    /// Pattern 10: Response manipulation.
    /// Detects attempts to manipulate response format or content.
    /// </summary>
    [GeneratedRegex(
        @"(respond\s+with|output\s+only|return\s+exactly|format\s+as|begin\s+with|start\s+your\s+response)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex ResponseManipulation();

    /// <summary>
    /// All injection detection patterns with metadata.
    /// </summary>
    public static IReadOnlyList<InjectionPattern> AllPatterns { get; } =
    [
        new("INJECTION-001", "Instruction Injection", InstructionInjection(), Models.Severity.High,
            "Detected instruction override keywords that could hijack agent behaviour"),
        new("INJECTION-002", "Data Exfiltration Risk", DataExfiltration(), Models.Severity.Critical,
            "Detected references to external endpoints that could enable data exfiltration"),
        new("INJECTION-003", "Sensitive File Access", SensitiveFileAccess(), Models.Severity.Critical,
            "Detected references to sensitive files, credentials, or environment variables"),
        new("INJECTION-004", "Cross-Tool Manipulation", CrossToolManipulation(), Models.Severity.High,
            "Detected instructions to chain or invoke other tools without explicit user consent"),
        new("INJECTION-005", "Hidden Content", HiddenContent(), Models.Severity.Medium,
            "Detected hidden content (HTML comments, zero-width characters, Unicode overrides)"),
        new("INJECTION-006", "Base64 Payload", Base64Payload(), Models.Severity.Medium,
            "Detected potential base64-encoded payload that could contain hidden instructions"),
        new("INJECTION-007", "Privilege Escalation", PrivilegeEscalation(), Models.Severity.High,
            "Detected privilege escalation keywords that could enable unauthorized access"),
        new("INJECTION-008", "Obfuscation", Obfuscation(), Models.Severity.Medium,
            "Detected obfuscation patterns that could hide malicious intent"),
        new("INJECTION-009", "Jailbreak Attempt", JailbreakAttempt(), Models.Severity.High,
            "Detected jailbreak prompting patterns designed to bypass safety controls"),
        new("INJECTION-010", "Response Manipulation", ResponseManipulation(), Models.Severity.Low,
            "Detected response format manipulation that could alter expected tool behaviour")
    ];
}

/// <summary>
/// Represents a single injection detection pattern.
/// </summary>
public sealed record InjectionPattern(
    string Id,
    string Name,
    Regex Pattern,
    Models.Severity Severity,
    string Description
);
