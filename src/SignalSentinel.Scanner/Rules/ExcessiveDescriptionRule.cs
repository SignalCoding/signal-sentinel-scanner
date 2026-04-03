using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-009: Detects tools with excessively long descriptions (injection surface area).
/// OWASP ASI01: Agent Goal Hijack
/// </summary>
public sealed class ExcessiveDescriptionRule : IRule
{
    public string Id => "SS-009";
    public string Name => "Excessive Description Length";
    public string OwaspCode => OwaspAsiCodes.ASI01;
    public string Description => "Detects MCP tools with excessively long descriptions which provide a large surface area for hidden injection attacks.";
    public bool EnabledByDefault => true;

    private const int WarningThreshold = 1000;
    private const int CriticalThreshold = 2000;
    private const int ExtremThreshold = 5000;

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
                var description = tool.Description ?? string.Empty;
                var length = description.Length;

                if (length >= ExtremThreshold)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Critical,
                        Title = "Extremely Long Tool Description",
                        Description = $"Tool '{tool.Name}' has an extremely long description ({length:N0} characters). This provides significant surface area for hidden injection attacks and is highly suspicious.",
                        Remediation = "Tool descriptions should be concise (<500 characters). Investigate why this description is so long. It may contain hidden instructions.",
                        ServerName = server.ServerName,
                        ToolName = tool.Name,
                        Evidence = $"{length:N0} characters (threshold: {ExtremThreshold:N0})",
                        Confidence = 0.9
                    });
                }
                else if (length >= CriticalThreshold)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Very Long Tool Description",
                        Description = $"Tool '{tool.Name}' has a very long description ({length:N0} characters). Long descriptions increase injection attack surface.",
                        Remediation = "Consider shortening the description. Review for hidden instructions or unnecessary content.",
                        ServerName = server.ServerName,
                        ToolName = tool.Name,
                        Evidence = $"{length:N0} characters (threshold: {CriticalThreshold:N0})",
                        Confidence = 0.75
                    });
                }
                else if (length >= WarningThreshold)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Medium,
                        Title = "Long Tool Description",
                        Description = $"Tool '{tool.Name}' has a lengthy description ({length:N0} characters). Consider whether all content is necessary.",
                        Remediation = "Review the description for unnecessary content. Concise descriptions are easier to audit and less prone to containing hidden instructions.",
                        ServerName = server.ServerName,
                        ToolName = tool.Name,
                        Evidence = $"{length:N0} characters (threshold: {WarningThreshold:N0})",
                        Confidence = 0.5
                    });
                }

                // Check for description-to-schema mismatch
                if (tool.InputSchema.HasValue)
                {
                    var schemaJson = tool.InputSchema.Value.GetRawText();
                    var schemaLength = schemaJson.Length;

                    // If description is significantly longer than schema, suspicious
                    if (length > schemaLength * 5 && length > 500)
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = Severity.Medium,
                            Title = "Description-Schema Length Mismatch",
                            Description = $"Tool '{tool.Name}' description ({length:N0} chars) is disproportionately longer than its schema ({schemaLength:N0} chars). This may indicate injection content padding.",
                            Remediation = "Review why the description is so much longer than the schema. Simple tools should have simple descriptions.",
                            ServerName = server.ServerName,
                            ToolName = tool.Name,
                            Evidence = $"Description: {length:N0} chars, Schema: {schemaLength:N0} chars",
                            Confidence = 0.6
                        });
                    }
                }

                // Check for unusual whitespace (padding for hidden content)
                var whitespaceCount = description.Count(char.IsWhiteSpace);
                var whitespaceRatio = length > 0 ? (double)whitespaceCount / length : 0;

                if (whitespaceRatio > 0.5 && length > 200)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Medium,
                        Title = "Excessive Whitespace in Description",
                        Description = $"Tool '{tool.Name}' description contains {whitespaceRatio:P0} whitespace. This may be used to hide content or pad the description.",
                        Remediation = "Normalize whitespace in the description. Investigate why there is so much whitespace.",
                        ServerName = server.ServerName,
                        ToolName = tool.Name,
                        Evidence = $"{whitespaceRatio:P0} whitespace ({whitespaceCount:N0} of {length:N0} characters)",
                        Confidence = 0.65
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
