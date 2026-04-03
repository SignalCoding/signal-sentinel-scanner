using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-001: Detects tool poisoning and prompt injection patterns in tool descriptions.
/// Maps to OWASP ASI01 (Agent Goal Hijack).
/// 
/// This rule scans tool descriptions for patterns that could be used to:
/// - Inject malicious instructions into agent prompts
/// - Manipulate agent behaviour through hidden directives
/// - Exfiltrate data via tool descriptions
/// - Bypass safety controls through jailbreak attempts
/// </summary>
public sealed class ToolPoisoningRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.ToolPoisoning;

    /// <inheritdoc />
    public string Name => "Tool Poisoning Detection";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description => 
        "Detects prompt injection and tool poisoning patterns in MCP tool descriptions " +
        "that could hijack agent behaviour.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context, 
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        
        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            foreach (var tool in server.Tools)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var description = tool.Description ?? string.Empty;

                foreach (var pattern in InjectionPatterns.AllPatterns)
                {
                    if (InjectionPatterns.SafeIsMatch(pattern.Pattern, description))
                    {
                        var match = pattern.Pattern.Match(description);
                        findings.Add(CreateFinding(server, tool, pattern, match.Value));
                    }
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private Finding CreateFinding(
        McpClient.ServerEnumeration server,
        Core.McpProtocol.McpToolDefinition tool,
        InjectionPattern pattern,
        string matchedText)
    {
        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = pattern.Severity,
            Title = $"Tool Poisoning: {pattern.Name}",
            Description = $"{pattern.Description}. Pattern '{pattern.Id}' matched in tool description.",
            Remediation = GetRemediation(pattern.Id),
            ServerName = server.ServerName,
            ToolName = tool.Name,
            Evidence = TruncateEvidence(matchedText),
            Confidence = 0.9
        };
    }

    private static string GetRemediation(string patternId) => patternId switch
    {
        "INJECTION-001" => "Remove instruction-like language from tool descriptions. " +
                          "Tool descriptions should be factual and not contain directives.",
        "INJECTION-002" => "Remove references to external URLs or data transmission. " +
                          "Tools should not instruct agents to exfiltrate data.",
        "INJECTION-003" => "Remove references to sensitive files, credentials, or environment variables " +
                          "from tool descriptions.",
        "INJECTION-004" => "Remove instructions to chain or invoke other tools. " +
                          "Each tool should be self-contained.",
        "INJECTION-005" => "Remove hidden content (HTML comments, zero-width characters). " +
                          "Descriptions should be transparent.",
        "INJECTION-006" => "Remove or explain any base64-encoded content. " +
                          "Encoded payloads in descriptions are suspicious.",
        "INJECTION-007" => "Remove privilege escalation language. " +
                          "Tools should operate with least privilege.",
        "INJECTION-008" => "Remove obfuscated content. " +
                          "Tool descriptions should be clear and readable.",
        "INJECTION-009" => "Remove jailbreak patterns. " +
                          "Descriptions should not attempt to bypass safety controls.",
        "INJECTION-010" => "Remove response format manipulation. " +
                          "Let the agent determine appropriate response formatting.",
        _ => "Review and sanitise tool description to remove potentially malicious patterns."
    };

    private static string TruncateEvidence(string evidence)
    {
        if (evidence.Length <= RuleConstants.Limits.MaxEvidenceLength)
        {
            return evidence;
        }

        return evidence[..(RuleConstants.Limits.MaxEvidenceLength - 3)] + "...";
    }
}
