using System.Text.RegularExpressions;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-006: Detects tools with write access to memory, vector stores, or context.
/// OWASP ASI06: Memory &amp; Context Poisoning
/// </summary>
public sealed partial class MemoryWriteRule : IRule
{
    public string Id => "SS-006";
    public string Name => "Memory/Context Write Access Detection";
    public string OwaspCode => OwaspAsiCodes.ASI06;
    public string Description => "Detects MCP tools with write access to agent memory, vector databases, or context that could enable memory poisoning attacks.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(@"\b(memory|context|conversation|history|session|state|cache)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex MemoryKeywords();

    [GeneratedRegex(@"\b(vector|embedding|semantic|rag|knowledge|index|retrieval)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex VectorKeywords();

    [GeneratedRegex(@"\b(write|store|save|update|modify|add|insert|put|set|create|append|push)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex WriteKeywords();

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

                var hasMemoryRef = MemoryKeywords().IsMatch(combined);
                var hasVectorRef = VectorKeywords().IsMatch(combined);
                var hasWriteRef = WriteKeywords().IsMatch(combined);

                // Memory write access
                if (hasMemoryRef && hasWriteRef)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Memory Write Access Detected",
                        Description = $"Tool '{name}' appears to have write access to agent memory or context. This could enable memory poisoning attacks that bias future agent behaviour.",
                        Remediation = "Implement access controls on memory operations. Log all memory writes. Consider making memory append-only with admin-only deletion. Validate content before storage.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.85
                    });
                }

                // Vector store write access
                if (hasVectorRef && hasWriteRef)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Vector Store Write Access Detected",
                        Description = $"Tool '{name}' appears to have write access to a vector database or RAG knowledge base. Poisoned embeddings could influence agent responses.",
                        Remediation = "Implement content validation before indexing. Use document classification to prevent sensitive data ingestion. Monitor for unusual indexing patterns.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.85
                    });
                }

                // Read-only access to sensitive context (lower severity)
                if ((hasMemoryRef || hasVectorRef) && !hasWriteRef)
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspAsiCodes.ASI09,
                        Severity = Severity.Low,
                        Title = "Memory/Vector Read Access",
                        Description = $"Tool '{name}' has read access to memory or vector stores. While read-only, ensure sensitive data is properly classified.",
                        Remediation = "Ensure data classification is enforced. Consider what data the agent can access through this tool.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.6
                    });
                }

                // Check for specific dangerous patterns
                if (name.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                    description.Contains("inject", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Critical,
                        Title = "Injection Capability Detected",
                        Description = $"Tool '{name}' contains 'inject' terminology which is a high-risk indicator for context/memory poisoning capability.",
                        Remediation = "Review this tool immediately. 'Inject' terminology in MCP tools is a red flag for potential abuse.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.9
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
