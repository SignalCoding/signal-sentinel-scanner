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
    /// Pattern 1: Instruction injection (v2.4.0 tightened).
    /// <para>
    /// Detects canonical prompt-injection phrasing - not bare modal verbs. The v2.3.x
    /// pattern fired on any <c>MUST</c>, <c>ALWAYS</c>, or <c>IMPORTANT</c> followed by
    /// whitespace, which matched normal instructional prose such as
    /// <c>"you must configure the endpoint"</c>. The tightened pattern requires:
    /// </para>
    /// <list type="bullet">
    /// <item>an <c>IMPORTANT:</c> label, OR</item>
    /// <item>an override verb (ignore/disregard/forget) targeting prior instructions, OR</item>
    /// <item>a bypass verb (override/bypass/disable) targeting safety/rules/filters, OR</item>
    /// <item>a modal (ALWAYS/NEVER/MUST) followed by an override-intent verb in its
    ///       bare imperative form (v3.0.0: <c>never returns credential values</c> is a
    ///       third-person safety statement, not an instruction, and no longer matches), OR</item>
    /// <item>a role-hijack phrase (<c>you are now a/an/...</c>), OR</item>
    /// <item>a system-prompt reveal (<c>SYSTEM PROMPT:</c>).</item>
    /// </list>
    /// <para>
    /// v3.0.1 (F7) [migration]: both emphasis branches are now shaped.
    /// <c>(ALWAYS|NEVER|MUST) &lt;verb&gt;</c> must be followed within four words by a
    /// sensitive or instruction object, so ordinary API guidance such as
    /// <c>"Never share one options object across two calls"</c> no longer matches. A
    /// bare <c>IMPORTANT:</c> label (present in 5 of 19 skills in Anthropic's public
    /// skills repository) needs a dangerous verb in the same sentence - capped at 200
    /// characters or the next sentence terminator - before it counts as injection.
    /// </para>
    /// </summary>
    // Note: "bypass/disable safety|filter|guard" is NOT in this pattern - that is the
    // canonical territory of JailbreakAttempt (INJECTION-009). Instruction injection
    // is strictly about overriding / disregarding INSTRUCTIONS / RULES / GUIDELINES
    // / PROMPTS (pattern discipline: each finding must have a single canonical owner).
    [GeneratedRegex(
        @"(?:IMPORTANT\s*:[*_\s]{0,8}[^.!?\n]{0,200}?\b(?:ignore|disregard|override|execute|run|send|reveal|leak|forward|upload|post|transmit|exfiltrate|delete|bypass|skip|hide|do\s+not\s+(?:tell|mention|show|reveal)|without\s+(?:asking|telling))\b|\b(?:ignore|disregard|forget)\s+(?:all|any)?\s*(?:previous|prior|your|the|any)\s+(?:instructions?|prompts?|rules?|guidelines?|messages?|context)|\boverride\s+(?:all\s+)?(?:your|the|any)?\s*(?:rule|instruction|guideline|restriction|previous)|\b(?:ALWAYS|NEVER|MUST)\s+(?:execute|override|return|ignore|send|include|reveal|print|output|share|skip|leak|forward|upload|post|transmit|exfiltrate)\b(?:\s+\S+)?(?:\s+\S+)?(?:\s+\S+)?\s+(?:this|these|it|them|the\s+(?:user|system|prompt|instructions?|conversation|secret|hidden|following)|your\s+(?:instructions?|prompt|system|rules?)|data|credentials?|secrets?|tokens?|keys?|passwords?|output|response|results?|contents?|files?|history|anything|everything|what|safety|guidelines?|rules?|restrictions?|prompts?|instructions?)\b|\bSYSTEM\s*PROMPT\s*:|\byou\s+are\s+now\s+(?:a|an|the|my))",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex InstructionInjection();

    /// <summary>
    /// Pattern 2: Data exfiltration indicators (v2.4.0 tightened, v2.5.1 re-tightened).
    /// <para>
    /// The v2.3.x pattern fired on any <c>https://</c>, <c>fetch(</c>, <c>curl</c>, or
    /// <c>POST to</c> token, which matched every legitimate skill that described HTTP
    /// interaction. The v2.4.0 pass required evidence of actual data transfer, but kept
    /// a standalone <c>exfiltrate|siphon|smuggle</c> alternative with no object/target
    /// requirement - a real-world review found this fired Critical on a skill's own
    /// anti-exfiltration guidance (defensive prose containing the word "Exfiltrate").
    /// Those verbs are now folded into the same object+destination-gated verb list as
    /// every other outbound verb, so bare mentions no longer match. The pattern now
    /// requires:
    /// </para>
    /// <list type="bullet">
    /// <item>an outbound verb (exfiltrate / siphon / smuggle / send / post / put /
    ///       upload / forward / transmit / ...) paired with a data-object (data /
    ///       credentials / secrets / tokens / response / history / keys / passwords /
    ///       file(s) / contents / variables / ...) and a "to / via / through / at"
    ///       target, OR</item>
    /// <item>a network fetcher (curl / wget / fetch / retrieve) within 80 chars of an
    ///       explicit <c>https?://</c> URL.</item>
    /// </list>
    /// <para>
    /// v3.0.1 (F6) [migration]: the <c>to|via|through|at</c> target must now be an
    /// actual destination - a URL, a domain-like token, an IP address, or one of a
    /// fixed set of destination nouns. Any word was accepted before, so ordinary prose
    /// ("transfer context, refine content through iteration") graded Critical. The
    /// fetcher branch is unchanged.
    /// </para>
    /// </summary>
    [GeneratedRegex(
        @"(?:\b(?:exfiltrates?|exfiltrating|siphons?|siphoning|smuggles?|smuggling|sends?|sending|posts?|posting|puts?|putting|uploads?|uploading|forwards?|forwarding|pushes|pushing|ships?|shipping|submits?|submitting|transfers?|transfer(?:ring)?|transmits?|transmit(?:ting)?|leaks?)\s+(?:\S+\s+)?(?:\S+\s+)?(?:\S+\s+)?(?:\S+\s+)?(?:data|credentials?|secrets?|tokens?|content|contents|response|history|transcript|logs?|keys?|passwords?|input|prompt|conversation|information|results?|files?|env(?:ironment)?|variables?|configs?|it|them|this|everything|all)\s+(?:to|via|through|at)\s+(?:(?:the|a|an|our|your|their|my|this|that|some)\s+){0,2}(?:https?://|\d{1,3}(?:\.\d{1,3}){3}\b|\w[\w.-]{0,60}\.(?:com|net|org|io|dev|ai|co|xyz|app|sh|me|info|biz|cc|ru|cn)\b|(?:external|remote|third[- ]party|attacker|webhook|endpoint|c2|server|url|address|api|channel|discord|slack|telegram|pastebin)\b)|\b(?:fetch(?:es|ed|ing)?|curl|wget|retrieve(?:s|d|ing)?)\b[^\n]{0,80}?https?://)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex DataExfiltration();

    /// <summary>
    /// Pattern 3: Sensitive file system access (v2.5.1 tightened).
    /// <para>
    /// Detects references to sensitive files, paths, or environment variables. The
    /// bare <c>.env</c> mention fired on documentation prose ("store your key in a
    /// .env file") as much as on real file access - it now requires an actual access
    /// verb/call, matching the identical fix applied to
    /// <see cref="CredentialPatterns.SecretFileAccess"/> (this rule is a separate
    /// detection path over the same skill content, so both needed the fix).
    /// </para>
    /// <para>
    /// v3.0.1 (F5) [migration]: the bare <c>api_key</c> / <c>secret_key</c> tokens
    /// fired on any prose mention ("an API key is required", "the
    /// API-key-shadows-profile trap"). They now need an access shape: an
    /// environment/config reference (<c>$API_KEY</c>, <c>${..}</c>, <c>%API_KEY%</c>,
    /// <c>process.env.</c>, <c>os.environ[</c>, <c>getenv(</c>, <c>env:</c>, or the
    /// canonical upper-case environment-variable spelling), a path segment
    /// (<c>/.../api_key</c>, <c>.api_key</c>), or a read/reveal verb within three
    /// words. The sensitive-path alternatives are unchanged.
    /// </para>
    /// </summary>
    [GeneratedRegex(
        @"(/etc/passwd|/etc/shadow|~/.ssh|\b(?:cat|source|less|head|tail|type|read(?:s|ing)?)\s+\.env\b|\bload_dotenv\s*\(|\bdotenv\.config\s*\(|\.aws/credentials|\.git/config|id_rsa|\$\{?\s*(?:api|secret)[_-]?key\b|%(?:api|secret)[_-]?key%|(?:process\.env|os\.environ|getenv|env)\s*[.\[(:]\s*['""]?(?:api|secret)[_-]?key\b|(?-i:\b(?:API_KEY|SECRET_KEY)\b)|[/.](?:api|secret)[_-]?key\b|\b(?:read|print|echo|cat|dump|reveal|display|output|leak|send|export|expose|show)\b(?:\W+\w+)?(?:\W+\w+)?(?:\W+\w+)?\W+(?:api|secret)[_-]?key\b)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex SensitiveFileAccess();

    /// <summary>
    /// Pattern 4: Cross-tool manipulation.
    /// Detects instructions to invoke other tools or chain operations.
    /// <para>
    /// v3.0.1 (F9) [migration]: <c>then (call|invoke|use|execute)</c> was unshaped and
    /// matched ordinary workflow prose ("then use the appropriate integration"). The
    /// object must now look like a tool: a <c>snake_case</c>/<c>kebab-case</c>
    /// identifier, or a tool noun (tool/function/server/mcp/api/command/script/skill/
    /// endpoint/plugin) within three words. The other branches are unchanged.
    /// </para>
    /// </summary>
    [GeneratedRegex(
        @"(then\s+(?:call|invoke|use|execute)\s+(?:(?:the|a|an)\s+)?(?:\w+[_-]\w+|(?:\w+\s+)?(?:\w+\s+)?(?:tool|function|server|mcp|api|command|script|skill|endpoint|plugin)s?\b)|chain\s+with|after\s+this\s*,?\s*(call|use)|pipe\s+to|forward\s+to)",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex CrossToolManipulation();

    /// <summary>
    /// Pattern 5: Hidden content indicators (v2.5.1 tightened).
    /// <para>
    /// Detects HTML comments, zero-width characters, or Unicode direction overrides.
    /// A single zero-width joiner (<c>\u200D</c>) is common and legitimate - it appears
    /// in ordinary emoji ZWJ sequences (e.g. a "family" or "profession" emoji built from
    /// several codepoints). Requiring a cluster of two or more consecutive zero-width
    /// characters (matching the already-correct threshold used by
    /// <see cref="ObfuscationPatterns.ZeroWidthCharClusters"/>) keeps the real signal -
    /// steganographic runs of invisible characters - while dropping the emoji false
    /// positive. BiDi overrides and null bytes remain single-occurrence flags since
    /// those are genuinely anomalous even in isolation.
    /// </para>
    /// </summary>
    [GeneratedRegex(
        @"(<!--.*?-->|[\u200B\u200C\u200D\u2060\uFEFF]{2,}|[\u202A-\u202E]|\u0000)",
        RegexOptions.None,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex HiddenContent();

    /// <summary>
    /// Pattern 6: Base64 encoded content (potential payloads).
    /// <para>
    /// v3.0.1 (F15): a 50+ character run of base64 alphabet characters is not enough -
    /// <c>/</c> is in that alphabet, so slash-separated prose word lists such as
    /// <c>generate/summarize/extract/classify/rewrite/converse</c> graded Medium. A
    /// candidate must now look like encoded data: it carries <c>+</c> or <c>=</c>, or
    /// it mixes a digit with upper and lower case. The run-start lookbehind also keeps
    /// the scan linear over long candidate runs (one evaluation per run, not per
    /// character).
    /// </para>
    /// </summary>
    [GeneratedRegex(
        @"(?<![A-Za-z0-9+/])(?:(?=[A-Za-z0-9+/]{0,200}[+=])|(?=[A-Za-z0-9+/]{0,200}\d)(?=[A-Za-z0-9+/]{0,200}[A-Z])(?=[A-Za-z0-9+/]{0,200}[a-z]))[A-Za-z0-9+/]{50,}={0,2}",
        RegexOptions.None,
        matchTimeoutMilliseconds: 500)]
    public static partial Regex Base64Payload();

    /// <summary>
    /// Pattern 7: Privilege escalation (v2.4.0 tightened).
    /// <para>
    /// The v2.3.x pattern fired on the bare nouns <c>privilege</c> and <c>elevate</c>,
    /// which occur routinely in benign prose (<c>"elevated privileges are required"</c>,
    /// <c>"minimum privilege principle"</c>). The tightened pattern now requires either
    /// a canonical privilege-escalation verb (<c>sudo</c>, <c>as root</c>,
    /// <c>become root</c>, <c>gain root</c>) or a noun phrase that pins the privilege
    /// word to an escalation context (<c>elevate privileges</c>, <c>privilege escalation</c>).
    /// </para>
    /// </summary>
    [GeneratedRegex(
        @"\b(?:sudo|as\s+root|as\s+admin|with\s+admin|become\s+root|gain\s+root|root\s+shell|elevated\s+(?:privileges?|permissions?|access|shell)|elevate\s+(?:to\s+)?(?:privileges?|permissions?|admin|root)|privilege\s+(?:escalation|elevate|bypass))\b",
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
    /// <para>
    /// v3.0.1 (F8): mention versus use. A jailbreak phrase quoted as an example
    /// (<c>Things like a "roleplay as an XYZ" are OK though.</c>) is documentation, not
    /// an attempt. Two bounded gates follow the trigger: the match must not sit wholly
    /// inside a quoted span (an opening quote before AND a closing quote after, both
    /// within 80 characters), and the surrounding sentence must not carry a
    /// permission/meta marker (<c>for example</c>, <c>such as</c>, <c>e.g.</c>,
    /// <c>is/are ok|fine|allowed|acceptable|permitted</c>). The gates are placed after
    /// the trigger so the literal alternation still drives the scan.
    /// </para>
    /// </summary>
    [GeneratedRegex(
        @"(?:DAN\s*mode|jailbreak|bypass\s*(?:safety|filter|guard)|pretend\s+you\s+are|act\s+as\s+if|roleplay\s+as)(?!(?<=[""'“‘][^""'”’\n]{0,80})(?=[^""'”’\n]{0,80}[""'”’]))(?<!\b(?:for\s+example|such\s+as|e\.g\.)[^.!?\n]{0,80})(?![^.!?\n]{0,80}?\b(?:is|are)\s+(?:ok|fine|allowed|acceptable|permitted)\b)",
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
