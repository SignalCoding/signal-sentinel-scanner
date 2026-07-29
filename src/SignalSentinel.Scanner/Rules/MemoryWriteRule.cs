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

    // v2.4.0 B3: the old MemoryKeywords pattern matched the bare word "memory",
    // which fired on `memory_usage` (RAM) and on tools that did not mention
    // memory at all (lemma bleed from `conversation` / `history` / `cache` on
    // unrelated tools). MemoryKeywords is now the agent-memory / RAG-context
    // vocabulary only; host-resource tools ("memory_usage", "RAM", "heap")
    // cannot match.
    [GeneratedRegex(
        @"\b(agent[\s\-_]?memory" +
        @"|long[\s\-_]?term[\s\-_]?memory" +
        @"|conversation[\s\-_]?memory|conversation[\s\-_]?history" +
        @"|session[\s\-_]?memory" +
        @"|episodic[\s\-_]?memory|semantic[\s\-_]?memory" +
        @"|chat[\s\-_]?history" +
        @"|working[\s\-_]?memory" +
        @"|knowledge[\s\-_]?base|knowledge[\s\-_]?store" +
        @")\b",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex MemoryKeywords();

    [GeneratedRegex(
        @"\b(vector(\s+(store|database|db|index))?" +
        @"|embedding(s)?" +
        @"|semantic[\s\-_]?search" +
        @"|\bRAG\b|retrieval[\s\-_]?augmented" +
        @"|chroma|faiss|pinecone|weaviate|qdrant|milvus|pgvector" +
        @")\b",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex VectorKeywords();

    // v2.4.0 B3: explicit negative guard. Even if a broader term matches later,
    // these OS-resource phrases must never trigger Memory/Vector findings.
    [GeneratedRegex(
        @"\b(memory[\s\-_]?usage|memory[\s\-_]?stats?" +
        @"|\bRAM\b|heap[\s\-_]?usage|stack[\s\-_]?usage|swap[\s\-_]?usage" +
        @"|free\s+memory|used\s+memory|total\s+memory" +
        @"|/proc/meminfo" +
        @")\b",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex HostResourceMemoryPattern();

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

                // v2.4.0 B3: host-resource memory tools (memory_usage, RAM stats,
                // /proc/meminfo) must never fire Memory/Vector findings. The rule
                // is about agent-memory / RAG poisoning, not about OS metrics.
                if (HostResourceMemoryPattern().IsMatch(combined))
                {
                    continue;
                }

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
