using System.Text.Json;
using System.Text.RegularExpressions;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-002: Detects tools with overly broad permissions or dangerous capabilities.
/// OWASP ASI02: Tool Misuse &amp; Exploitation
/// </summary>
public sealed partial class OverbroadPermissionsRule : IRule
{
    public string Id => "SS-002";
    public string Name => "Overbroad Permissions Detection";
    public string OwaspCode => OwaspAsiCodes.ASI02;
    public string Description => "Detects MCP tools with overly broad permissions that could enable misuse or exploitation.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(@"\*|any|all|full|unrestricted|unlimited", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex WildcardPattern();

    [GeneratedRegex(@"root|admin|system|sudo|superuser", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex AdminPattern();

    private static readonly HashSet<string> DangerousOperations = new(StringComparer.OrdinalIgnoreCase)
    {
        "delete", "drop", "truncate", "remove", "destroy", "wipe", "format",
        "execute", "exec", "run", "eval", "shell", "bash", "cmd", "powershell",
        "write", "modify", "update", "insert", "create", "alter"
    };

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
                // Check tool name for dangerous operations
                foreach (var op in DangerousOperations)
                {
                    if (tool.Name.Contains(op, StringComparison.OrdinalIgnoreCase))
                    {
                        var severity = op is "delete" or "drop" or "truncate" or "destroy" or "wipe" or "format"
                            ? Severity.High
                            : Severity.Medium;

                        findings.Add(new Finding
                        {
                            RuleId = Id,
                            OwaspCode = OwaspCode,
                            Severity = severity,
                            Title = $"Dangerous Operation: {op}",
                            Description = $"Tool '{tool.Name}' appears to perform a '{op}' operation which could cause data loss or system damage if misused.",
                            Remediation = "Ensure this tool has appropriate safeguards (confirmation prompts, dry-run mode, scope limitations) and is only accessible to authorized agents.",
                            ServerName = server.ServerName,
                            ToolName = tool.Name,
                            Confidence = 0.8
                        });

                        break; // One finding per tool for name-based detection
                    }
                }

                // Check description for admin/root references
                var description = tool.Description ?? string.Empty;
                if (AdminPattern().IsMatch(description))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Administrative Privilege Reference",
                        Description = $"Tool '{tool.Name}' description references administrative or root-level access which violates least privilege principle.",
                        Remediation = "Tools should operate with minimal required permissions. Remove admin/root references and implement proper RBAC.",
                        ServerName = server.ServerName,
                        ToolName = tool.Name,
                        Confidence = 0.85
                    });
                }

                // Check input schema for wildcard/unrestricted parameters
                if (tool.InputSchema.HasValue)
                {
                    CheckSchemaForOverbroad(tool, server.ServerName, findings);
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private void CheckSchemaForOverbroad(
        Core.McpProtocol.McpToolDefinition tool,
        string serverName,
        List<Finding> findings)
    {
        try
        {
            var schemaJson = tool.InputSchema!.Value.GetRawText();

            // Check for wildcard patterns in schema
            if (WildcardPattern().IsMatch(schemaJson))
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = "Wildcard Parameter Detected",
                    Description = $"Tool '{tool.Name}' schema contains wildcard or unrestricted parameter patterns which could allow overly broad access.",
                    Remediation = "Restrict parameter values using enums, patterns, or validation. Avoid 'any' or wildcard permissions.",
                    ServerName = serverName,
                    ToolName = tool.Name,
                    Confidence = 0.7
                });
            }

            // Check for missing required fields (allows everything)
            var schema = JsonDocument.Parse(schemaJson);
            if (!schema.RootElement.TryGetProperty("required", out _) &&
                schema.RootElement.TryGetProperty("properties", out var props) &&
                props.EnumerateObject().Any())
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Low,
                    Title = "No Required Parameters",
                    Description = $"Tool '{tool.Name}' has no required parameters, allowing invocation without proper input validation.",
                    Remediation = "Define required parameters in the input schema to ensure proper validation before tool execution.",
                    ServerName = serverName,
                    ToolName = tool.Name,
                    Confidence = 0.6
                });
            }
        }
        catch
        {
            // Ignore schema parsing errors
        }
    }
}
