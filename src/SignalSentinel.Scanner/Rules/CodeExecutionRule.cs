using System.Text.RegularExpressions;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-005: Detects tools that expose code execution capabilities.
/// OWASP ASI05: Unexpected Code Execution
/// </summary>
public sealed partial class CodeExecutionRule : IRule
{
    public string Id => "SS-005";
    public string Name => "Code Execution Capability Detection";
    public string OwaspCode => OwaspAsiCodes.ASI05;
    public string Description => "Detects MCP tools that expose code execution capabilities which could be exploited for arbitrary code execution.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(@"\b(exec|eval|execute|run|spawn|shell|bash|cmd|powershell|subprocess|system|popen|compile|interpret)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex CodeExecutionKeywords();

    [GeneratedRegex(@"\b(python|node|ruby|perl|php|javascript|typescript|script)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex LanguageKeywords();

    [GeneratedRegex(@"\b(code|command|script|expression|statement|query)\s*(input|parameter|arg)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex CodeInputPattern();

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

                // Check for code execution keywords in name
                if (CodeExecutionKeywords().IsMatch(name))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Critical,
                        Title = "Code Execution Tool Detected",
                        Description = $"Tool '{name}' appears to provide code execution capabilities based on its name. This is a high-risk capability that could be exploited for arbitrary code execution.",
                        Remediation = "If code execution is required, implement strict sandboxing, input validation, and allowlisted commands. Consider using safer alternatives like pre-defined actions.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.95
                    });
                }
                else if (CodeExecutionKeywords().IsMatch(description))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Code Execution Capability Referenced",
                        Description = $"Tool '{name}' description references code execution capabilities. Review carefully to ensure proper security controls are in place.",
                        Remediation = "Implement input validation, output sanitisation, and execution sandboxing. Log all execution attempts for audit.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Evidence = TruncateMatch(CodeExecutionKeywords().Match(description).Value),
                        Confidence = 0.8
                    });
                }

                // Check for language interpreter references
                if (LanguageKeywords().IsMatch(combined))
                {
                    var match = LanguageKeywords().Match(combined);
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Medium,
                        Title = "Language Interpreter Reference",
                        Description = $"Tool '{name}' references a programming language interpreter ({match.Value}). This may indicate code execution capability.",
                        Remediation = "If the tool executes user-provided code, implement strict sandboxing and resource limits. Consider using language-specific security measures.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Evidence = match.Value,
                        Confidence = 0.7
                    });
                }

                // Check input schema for code/command parameters
                if (tool.InputSchema.HasValue)
                {
                    var schemaJson = tool.InputSchema.Value.GetRawText();
                    if (CodeInputPattern().IsMatch(schemaJson))
                    {
                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = Severity.High,
                            Title = "Code Input Parameter Detected",
                            Description = $"Tool '{name}' accepts a code, command, or script parameter which could enable arbitrary code execution.",
                            Remediation = "Validate and sanitise all code inputs. Consider using an allowlist of permitted operations instead of arbitrary code execution.",
                            ServerName = server.ServerName,
                            ToolName = name,
                            Confidence = 0.85
                        });
                    }
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static string TruncateMatch(string value)
    {
        return value.Length > 50 ? value[..47] + "..." : value;
    }
}
