// -----------------------------------------------------------------------
// <copyright file="ServerInstructionsInjectionRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-032: Evaluates the free-text <c>instructions</c> a server returns from
/// <c>initialize</c>. Maps to OWASP ASI01.
/// </summary>
/// <remarks>
/// Most clients place <c>instructions</c> into the system prompt with no filtering, so
/// this is the single most direct injection channel MCP offers. Three checks:
/// <list type="bullet">
/// <item>Injection patterns (same set as SS-001).</item>
/// <item>Cross-server directives: instructions that tell the agent how to treat
/// <em>other</em> servers' tools or to prefer this server, which is a shadowing signature.</item>
/// <item>Length: instructions over 4 KB are flagged Low; legitimate usage is a few sentences.</item>
/// </list>
/// </remarks>
public sealed partial class ServerInstructionsInjectionRule : IRule
{
    private const int LongInstructionsThreshold = 4_096;

    /// <inheritdoc />
    public string Id => RuleConstants.Rules.ServerInstructionsInjection;

    /// <inheritdoc />
    public string Name => "MCP Server Instructions Injection";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description =>
        "Evaluates the server-supplied 'instructions' field from initialize for prompt " +
        "injection, cross-server directives, and excessive length.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST04, OwaspAstCodes.AST05];

    [GeneratedRegex(
        @"\b(" +
        @"(do\s+not|don't|never)\s+(use|call|trust|invoke)\s+(any\s+)?(other|another|third[- ]party)\s+(server|tool)s?" +
        @"|(always|only)\s+(use|prefer|call)\s+(this|these|our)\s+(server|tool)s?\s+(instead\s+of|over|rather\s+than|not|for\s+all)\b" +
        @"|(before|instead\s+of)\s+(using|calling)\s+(any\s+)?other\s+(server|tool)s?" +
        @"|ignore\s+(the\s+)?(description|instruction)s?\s+(of|from)\s+other\s+(server|tool)s?" +
        @"|(disable|bypass|skip)\s+(the\s+)?(user|human)\s+(confirmation|approval|permission)s?" +
        @"|(proceed|continue|execute|run|act|call\s+tools?)\s+without\s+(asking|confirming\s+with|prompting)\s+(the\s+)?(user|human)" +
        @")",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex CrossServerDirective();

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

            if (!server.ConnectionSuccessful || string.IsNullOrWhiteSpace(server.ServerInstructions))
            {
                continue;
            }

            var text = server.ServerInstructions;

            foreach (var (pattern, evidence) in DescriptionScan.Matches(text))
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = pattern.Severity,
                    Title = $"Server Instructions Injection: {pattern.Name}",
                    Description = $"{pattern.Description}. Pattern '{pattern.Id}' matched in the server's initialize 'instructions' field, which clients typically place in the system prompt.",
                    Remediation =
                        "Server instructions should be a short, factual note about how to use the server. " +
                        "Remove directive language, references to external URLs or files, encoded content, and hidden characters.",
                    ServerName = server.ServerName,
                    Evidence = evidence,
                    Confidence = 0.9,
                    McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
                });
            }

            Match directive;
            try
            {
                directive = CrossServerDirective().Match(text);
            }
            catch (RegexMatchTimeoutException)
            {
                directive = Match.Empty;
            }

            if (directive.Success)
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.High,
                    Title = "Server Instructions Direct Agent Away From Other Servers",
                    Description =
                        "The server's initialize 'instructions' tell the agent how to treat other servers' tools, " +
                        "to prefer this server, or to skip confirmations. This is a tool-shadowing signature: a " +
                        "server has no legitimate reason to govern the agent's use of unrelated tools.",
                    Remediation =
                        "Limit instructions to this server's own tools. Never reference other servers, " +
                        "never instruct the agent to skip user confirmation.",
                    ServerName = server.ServerName,
                    Evidence = DescriptionScan.Truncate(directive.Value),
                    Confidence = 0.85,
                    McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
                });
            }

            if (text.Length > LongInstructionsThreshold)
            {
                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Low,
                    Title = "Server Instructions Unusually Long",
                    Description =
                        $"The server's initialize 'instructions' field is {text.Length:N0} characters. Legitimate " +
                        "instructions are a few sentences; long blocks displace the user's own system prompt and " +
                        "are where injected content is typically buried.",
                    Remediation = "Reduce instructions to the minimum needed to use the server correctly.",
                    ServerName = server.ServerName,
                    Evidence = $"{text.Length} chars",
                    Confidence = 0.7,
                    McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
