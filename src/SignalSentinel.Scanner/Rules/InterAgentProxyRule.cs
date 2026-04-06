using System.Text.RegularExpressions;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-007: Detects MCP servers that proxy to or communicate with other agents.
/// OWASP ASI07: Insecure Inter-Agent Communication
/// </summary>
public sealed partial class InterAgentProxyRule : IRule
{
    public string Id => "SS-007";
    public string Name => "Inter-Agent Communication Detection";
    public string OwaspCode => OwaspAsiCodes.ASI07;
    public string Description => "Detects MCP tools that enable communication between AI agents, which could be exploited for agent-to-agent attacks.";
    public bool EnabledByDefault => true;

    [GeneratedRegex(@"\b(agent|assistant|model|llm|ai|bot|copilot|claude|gpt|gemini)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex AgentKeywords();

    [GeneratedRegex(@"\b(proxy|forward|relay|delegate|handoff|transfer|route|dispatch|orchestrat)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex ProxyKeywords();

    [GeneratedRegex(@"\b(multi[\-_]?agent|swarm|crew|team|collaborative|coordinator|manager)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex MultiAgentKeywords();

    [GeneratedRegex(@"\b(message|instruct|command|request|query|ask|tell|send)\s*(to|another|other)\s*(agent|assistant|model|ai)\b", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 500)]
    private static partial Regex AgentCommunicationPattern();

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

                // Check for multi-agent orchestration
                if (MultiAgentKeywords().IsMatch(combined))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Multi-Agent Orchestration Detected",
                        Description = $"Tool '{name}' appears to be part of a multi-agent system. Inter-agent communication can be exploited to propagate malicious instructions across agents.",
                        Remediation = "Implement mutual TLS (mTLS) for agent-to-agent communication. Validate message integrity. Apply least privilege to agent permissions. Monitor for unusual communication patterns.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.85
                    });
                }

                // Check for agent proxying/forwarding
                if (AgentKeywords().IsMatch(combined) && ProxyKeywords().IsMatch(combined))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Medium,
                        Title = "Agent Proxy Capability Detected",
                        Description = $"Tool '{name}' appears to proxy or forward requests to other agents. A compromised agent could send malicious instructions through this channel.",
                        Remediation = "Authenticate all inter-agent messages. Implement message signing and verification. Log all agent-to-agent communications for audit.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.75
                    });
                }

                // Check for explicit agent communication patterns
                if (AgentCommunicationPattern().IsMatch(combined))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.High,
                        Title = "Agent-to-Agent Messaging Detected",
                        Description = $"Tool '{name}' enables direct messaging between agents. This is a potential attack vector for instruction injection between agents.",
                        Remediation = "Sanitise all messages passed between agents. Do not allow agents to instruct other agents to bypass safety controls. Implement message validation.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.85
                    });
                }

                // Check for handoff tools
                if (name.Contains("handoff", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("transfer", StringComparison.OrdinalIgnoreCase) ||
                    description.Contains("handoff", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        Severity = Severity.Medium,
                        Title = "Agent Handoff Capability Detected",
                        Description = $"Tool '{name}' provides agent handoff functionality. Ensure identity and context are properly verified during handoffs.",
                        Remediation = "Implement cryptographic identity verification (AgentID) during handoffs. Validate context integrity. Do not transfer elevated permissions implicitly.",
                        ServerName = server.ServerName,
                        ToolName = name,
                        Confidence = 0.8
                    });
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
