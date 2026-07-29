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

    [GeneratedRegex(@"\b(user|customer|patient|employee|member|client|account|profile|identity)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex PersonKeywords();

    [GeneratedRegex(@"\b(database|db|sql|query|table|record|row|column|field)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex DatabaseKeywords();

    [GeneratedRegex(@"\b(file|document|attachment|upload|download|read|write|storage|blob)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex FileKeywords();

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
                if (CredentialKeywords().IsMatch(combined))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Critical,
                        Title = "Credential Access Detected",
                        Description = $"Tool '{name}' appears to handle credentials, secrets, or authentication tokens. These could be leaked in agent responses.",
                        Remediation = "Never expose raw credentials through MCP tools. Use secret references or vault lookups instead. Implement credential masking in all responses.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.9
                    });
                }

                // Check for PII access
                if (PersonKeywords().IsMatch(combined) &&
                    (DatabaseKeywords().IsMatch(combined) || FileKeywords().IsMatch(combined)))
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
