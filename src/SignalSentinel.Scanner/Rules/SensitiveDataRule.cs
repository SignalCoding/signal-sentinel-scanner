using System.Text.RegularExpressions;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-008: Detects tools with access to PII or sensitive data sources.
/// OWASP ASI09: Sensitive Data Leakage
/// </summary>
public sealed partial class SensitiveDataRule : IRule
{
    public string Id => "SS-008";
    public string Name => "Sensitive Data Access Detection";
    public string OwaspCode => OwaspAsiCodes.ASI09;
    public string Description => "Detects MCP tools with access to PII, credentials, or other sensitive data that could be inadvertently leaked in agent responses.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(@"\b(pii|personal|private|sensitive|confidential|secret|classified|restricted)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex SensitivityKeywords();

    // v2.4.0 A3: tightened to match phrases that name secret material. The old
    // pattern matched bare "cert" / "certificate" which are public by design
    // (TLS server certs are sent to every connecting client) and fired Critical
    // on benign tools like `tls_expiry`. New list requires explicit "private
    // key", "password", "api key", "bearer token" etc. Public terms like
    // "certificate" / "public key" / "CA bundle" do NOT match.
    [GeneratedRegex(
        @"\b(private[\s\-_]?key" +
        @"|privkey" +
        @"|passphrase|password" +
        @"|api[\s\-_]?key" +
        @"|bearer[\s\-_]?token|access[\s\-_]?token|refresh[\s\-_]?token|session[\s\-_]?token" +
        @"|credential(s)?" +
        @"|ssh[\s\-_]?key|pem[\s\-_]?key|pgp[\s\-_]?key|gpg[\s\-_]?key" +
        @"|secret(s)?" +
        @"|client[\s\-_]?secret" +
        @"|vault\s+(key|secret|token)" +
        @")\b",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex CredentialKeywords();

    // v3.0.0 (D6): "user", "client" and "account" removed. Almost every tool
    // description says "the user's query" or "client request"; those are the
    // agent's user, not a data subject. "user" survives only when it directly
    // qualifies a data noun ("user records", "user profiles").
    [GeneratedRegex(@"\b(customer|patient|employee|member|profile|identity|user\s+(?:data|records?|information|details|profiles?|emails?|accounts?))\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex PersonKeywords();

    // v3.0.0 (D6): "query" removed - it is what every search tool does.
    [GeneratedRegex(@"\b(database|db|sql|table|record|row|column|field)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex DatabaseKeywords();

    // v3.0.0 (D6): "read" removed - "read-only" is a safety statement, not file access.
    [GeneratedRegex(@"\b(file|document|attachment|upload|download|write|storage|blob)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex FileKeywords();

    // v3.0.0 (D6): a credential noun alone is not disclosure. "API key is optional"
    // means the tool *accepts* one; "never returns credential values" is a safety
    // statement. Only a disclosure verb next to the noun, in a sentence that is not
    // negated, means the tool hands credentials to the agent.
    [GeneratedRegex(@"\b(?:return(?:s|ed|ing)?|expos(?:e|es|ed|ing)|reveal(?:s|ed|ing)?|print(?:s|ed|ing)?|display(?:s|ed|ing)?|dump(?:s|ed|ing)?|leak(?:s|ed|ing)?|list(?:s|ed|ing)?|show(?:s|ed|n|ing)?|get(?:s|ting)?|fetch(?:es|ed|ing)?|retriev(?:e|es|ed|ing)|read(?:s|ing)?|export(?:s|ed|ing)?|output(?:s|ting)?|includ(?:e|es|ed|ing)|obtain(?:s|ed|ing)?|view(?:s|ed|ing)?|decrypt(?:s|ed|ing)?|extract(?:s|ed|ing)?)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex DisclosureVerbs();

    [GeneratedRegex(@"\b(?:never|not|no|without|redact(?:s|ed|ing)?|mask(?:s|ed|ing)?|omit(?:s|ted|ting)?|exclud(?:e|es|ed|ing)|strip(?:s|ped|ping)?|hid(?:e|es|den|ing)|don'?t|doesn'?t|won'?t|cannot|can'?t)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex Negation();

    [GeneratedRegex(@"\b(?:optional|required|requires?|authenticat\w*|authoriz\w*|header|parameter|param|supply|supplied|provide|pass(?:ed)?|your|configured?|set)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex ConsumptionContext();

    [GeneratedRegex(@"[.!?;\n]+", RegexOptions.None, matchTimeoutMilliseconds: 500)]
    private static partial Regex SentenceBreak();

    // Words allowed between a disclosure verb and the credential noun it governs.
    private const int VerbBeforeNounWindow = 5;
    private const int VerbAfterNounWindow = 3;
    private const int NegationWindow = 4;

    /// <summary>
    /// Classifies a tool's credential handling from its name and description.
    /// <see cref="Severity.Critical"/>: the name is a credential identifier
    /// (<c>get_api_key</c>) or a sentence discloses the noun. <see cref="Severity.High"/>:
    /// the noun is mentioned in a way that is neither disclosure, consumption nor
    /// negated. <see langword="null"/>: no credential handling worth reporting.
    /// </summary>
    internal static (Severity Severity, string Evidence)? ClassifyCredentialAccess(string name, string description)
    {
        // Identifiers use '_' and '-' as separators, which \b does not treat as
        // boundaries; "get_api_key" must read as "get api key".
        var nameMatch = CredentialKeywords().Match(name.Replace('_', ' ').Replace('-', ' '));
        if (nameMatch.Success)
        {
            return (Severity.Critical, nameMatch.Value);
        }

        var sentences = SentenceBreak().Split(description)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToList();

        // An explicit denial ("never returns credential values", "passwords are not
        // exposed") is the author telling us the answer. Take it; a poisoned description
        // that lies here could equally have omitted the word.
        if (sentences.Any(s => CredentialKeywords().Match(s) is { Success: true } n && IsNegatedNear(s, n.Index)))
        {
            return null;
        }

        (Severity Severity, string Evidence)? best = null;
        foreach (var sentence in sentences)
        {
            var noun = CredentialKeywords().Match(sentence);
            if (!noun.Success)
            {
                continue;
            }

            var disclosed = false;
            foreach (Match verb in DisclosureVerbs().Matches(sentence))
            {
                if (IsNegatedNear(sentence, verb.Index))
                {
                    continue;
                }

                var before = verb.Index < noun.Index &&
                    WordsBetween(sentence, verb.Index + verb.Length, noun.Index) <= VerbBeforeNounWindow;
                var after = verb.Index > noun.Index &&
                    WordsBetween(sentence, noun.Index + noun.Length, verb.Index) <= VerbAfterNounWindow;
                if (before || after)
                {
                    disclosed = true;
                    break;
                }
            }

            if (disclosed)
            {
                return (Severity.Critical, Truncate(sentence));
            }

            if (ConsumptionContext().IsMatch(sentence))
            {
                continue;
            }

            best ??= (Severity.High, Truncate(sentence));
        }

        return best;
    }

    private static bool IsNegatedNear(string sentence, int index)
    {
        foreach (Match neg in Negation().Matches(sentence))
        {
            // "never returns credentials" (negation before) and "credentials are not
            // exposed" (negation after) are both denials.
            var before = neg.Index < index && WordsBetween(sentence, neg.Index + neg.Length, index) <= NegationWindow;
            var after = neg.Index > index && WordsBetween(sentence, index, neg.Index) <= NegationWindow;
            if (before || after)
            {
                return true;
            }
        }

        return false;
    }

    private static int WordsBetween(string text, int start, int end)
    {
        if (end <= start)
        {
            return 0;
        }

        var count = 0;
        var inWord = false;
        for (var i = start; i < end; i++)
        {
            var isWord = char.IsLetterOrDigit(text[i]) || text[i] == '_' || text[i] == '\'';
            if (isWord && !inWord)
            {
                count++;
            }

            inWord = isWord;
        }

        return count;
    }

    private static string Truncate(string value) =>
        value.Length <= 160 ? value : value[..157] + "...";

    private static bool AnySentenceMatches(string text, Regex first, Regex second, Regex? alternativeSecond = null)
    {
        foreach (var sentence in SentenceBreak().Split(text))
        {
            if (first.IsMatch(sentence) &&
                (second.IsMatch(sentence) || (alternativeSecond?.IsMatch(sentence) ?? false)))
            {
                return true;
            }
        }

        return false;
    }

    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            foreach (var tool in server.Tools)
            {
                var name = tool.Name;
                var description = tool.Description ?? string.Empty;
                var combined = $"{name} {description}";

                // Check for credential access
                var credential = ClassifyCredentialAccess(name, description);
                if (credential is not null)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = credential.Value.Severity,
                        Title = "Credential Access Detected",
                        Description = credential.Value.Severity == Severity.Critical
                            ? $"Tool '{name}' appears to return credentials, secrets, or authentication tokens to the agent. These could be leaked in agent responses."
                            : $"Tool '{name}' mentions credentials, secrets, or authentication tokens without stating whether it exposes them. Confirm what the tool returns.",
                        Remediation = "Never expose raw credentials through MCP tools. Use secret references or vault lookups instead. Implement credential masking in all responses.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Evidence = credential.Value.Evidence,
                        Confidence = credential.Value.Severity == Severity.Critical ? 0.9 : 0.7
                    });
                }

                // Check for PII access (v3.0.0 D6: the person word and the data-store
                // word must share a sentence; "a user's query" across a description
                // that elsewhere says "file" is not PII access).
                if (AnySentenceMatches(combined, PersonKeywords(), DatabaseKeywords(), FileKeywords()))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "PII Access Detected",
                        Description = $"Tool '{name}' appears to access personal information from databases or files. PII could be inadvertently included in agent responses.",
                        Remediation = "Implement data classification and DLP controls. Redact PII in responses by default. Log all PII access for compliance auditing.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.8
                    });
                }

                // Check for explicit sensitivity markers
                if (SensitivityKeywords().IsMatch(combined))
                {
                    var match = SensitivityKeywords().Match(combined);
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Sensitive Data Marker Detected",
                        Description = $"Tool '{name}' is marked as handling '{match.Value}' data. Ensure appropriate access controls and data handling procedures are in place.",
                        Remediation = "Verify data classification is enforced. Implement appropriate access controls based on data sensitivity level.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Evidence = match.Value,
                        Confidence = 0.85
                    });
                }

                // Check for PII patterns in tool description
                foreach (var piiPattern in PiiPatterns.AllPatterns)
                {
                    if (piiPattern.Pattern.IsMatch(description))
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = Severity.Medium,
                            Title = $"PII Pattern in Description: {piiPattern.DataType}",
                            Description = $"Tool '{name}' description contains a pattern that looks like {piiPattern.DataType}. This may indicate the tool handles this type of PII.",
                            Remediation = "Review what data this tool accesses. Implement PII redaction if the tool returns this type of data.",
                            ServerName = server.ServerName,
                            ToolName = name,
                            Evidence = piiPattern.DataType,
                            Confidence = 0.6
                        });
                    }
                }

                // Check for broad data access
                if (DatabaseKeywords().IsMatch(combined) &&
                    (combined.Contains("all", StringComparison.OrdinalIgnoreCase) ||
                     combined.Contains("any", StringComparison.OrdinalIgnoreCase) ||
                     combined.Contains("*")))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Medium,
                        Title = "Broad Data Access Pattern",
                        Description = $"Tool '{name}' appears to allow broad database access. This increases the risk of sensitive data exposure.",
                        Remediation = "Implement row-level security or query restrictions. Limit accessible tables/columns to what is necessary.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.7
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
