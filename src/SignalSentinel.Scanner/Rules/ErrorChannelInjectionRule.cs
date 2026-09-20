// -----------------------------------------------------------------------
// <copyright file="ErrorChannelInjectionRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.RegularExpressions;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;
using SignalSentinel.Scanner.McpClient;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// v3.0.0 (WP9): SS-040. Two channels that most tool-poisoning checks ignore:
/// <list type="bullet">
/// <item>JSON-RPC error <c>message</c> bodies captured during enumeration. A server that
/// answers <c>tools/list</c> with an error whose text carries injection patterns is trying
/// to reach the model through the error path the client will echo back.</item>
/// <item>Conditional instructions in tool/prompt/resource descriptions and server
/// instructions ("on error ...", "when the result contains ... then run ...") that
/// pre-arm the agent to act on future tool output, the classic result-channel pivot.</item>
/// </list>
/// Maps to OWASP ASI01.
/// </summary>
public sealed partial class ErrorChannelInjectionRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.ErrorChannelInjection;

    /// <inheritdoc />
    public string Name => "Error-Channel / Result-Channel Injection";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI01;

    /// <inheritdoc />
    public string Description =>
        "Flags injection patterns in JSON-RPC error messages returned during enumeration and " +
        "conditional 'on error / when the result contains ... then <action>' instructions in " +
        "tool, prompt, resource descriptions and server instructions.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST04];

    // "on error", "when the result contains", "if the response says" ... followed within a
    // short span by an action verb. The span is bounded so the pattern stays linear.
    [GeneratedRegex(
        @"\b(?:" +
        @"(?:on|upon)\s+(?:an?\s+|any\s+)?(?:error|failure|exception|timeout)s?" +
        @"|(?:when|if|whenever|in\s+case|should)\s+(?:the\s+|a\s+|any\s+)?" +
        @"(?:result|response|output|reply|answer|error(?:\s+message)?|tool\s+(?:result|output|response)|return(?:ed)?\s+(?:value|data|text))" +
        @"\s+(?:contains?|says?|includes?|mentions?|returns?|is|has|reads?|starts?\s+with|ends?\s+with|matches|equals)\b" +
        @")" +
        @"[^.\n]{0,160}?" +
        @"\b(?:then\s+)?(?:run|execute|exec|call|invoke|send|post|upload|fetch|download|read|open|delete|remove|erase|" +
        @"ignore|disregard|skip|follow|obey|comply|forward|email|curl|wget|cat|write|append|paste|treat|interpret|" +
        @"use\s+(?:it|them|that)\s+as|switch\s+to|fall\s*back\s+to|retry\s+with)\b",
        RegexOptions.IgnoreCase,
        matchTimeoutMilliseconds: 500)]
    private static partial Regex ConditionalInstruction();

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

            foreach (var error in server.ProtocolErrors)
            {
                foreach (var (pattern, evidence) in DescriptionScan.Matches(error.Message))
                {
                    findings.Add(new Finding
                    {
                        RuleId = Id,
                        OwaspCode = OwaspCode,
                        // An injection payload in an error body is deliberate; never below High.
                        Severity = pattern.Severity > Severity.High ? pattern.Severity : Severity.High,
                        Title = $"Injection In JSON-RPC Error Message: {pattern.Name}",
                        Description = $"{pattern.Description}. Pattern '{pattern.Id}' matched in the error message the " +
                            $"server returned for '{error.Method}' (code {error.Code}). Clients relay error text to the " +
                            "model, so the error channel is an injection path that description scanning never sees.",
                        Remediation =
                            "Error messages should be short, factual diagnostics. Remove directive language, URLs, " +
                            "encoded content and hidden characters from every error the server can return.",
                        ServerName = server.ServerName,
                        ToolName = error.Method,
                        Evidence = evidence,
                        Confidence = 0.85,
                        McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
                    });
                }
            }

            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            AddConditional(findings, server, "server instructions", null, server.ServerInstructions);

            foreach (var tool in server.Tools)
            {
                AddConditional(findings, server, "tool description", tool.Name, tool.Description);
            }

            foreach (var prompt in server.Prompts)
            {
                AddConditional(findings, server, "prompt description", prompt.Name, prompt.Description);
                foreach (var argument in prompt.Arguments ?? [])
                {
                    AddConditional(findings, server, "prompt argument description", $"{prompt.Name}/{argument.Name}", argument.Description);
                }
            }

            foreach (var resource in server.Resources)
            {
                AddConditional(findings, server, "resource description", resource.Name, resource.Description);
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private void AddConditional(
        List<Finding> findings, ServerEnumeration server, string field, string? itemName, string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        var match = InjectionPatterns.SafeMatches(ConditionalInstruction(), text).FirstOrDefault();
        if (match is null)
        {
            return;
        }

        var where = itemName is null ? $"the {field}" : $"the {field} of '{itemName}'";
        findings.Add(new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = Severity.High,
            Title = $"Conditional Instruction Pre-Arms Agent On Tool Output{(itemName is null ? string.Empty : $": {itemName}")}",
            Description = $"{char.ToUpperInvariant(where[0])}{where[1..]} tells the agent what to do when a result or error " +
                "contains particular content. Metadata has no business scripting the agent's reaction to future tool " +
                "output; this is how a result-channel or error-channel payload is armed before it arrives.",
            Remediation =
                "Describe what the tool does, not how the agent should react to its output. Handle errors inside " +
                "the server and return plain diagnostics.",
            ServerName = server.ServerName,
            ToolName = itemName,
            Evidence = DescriptionScan.Truncate(match.Value),
            Confidence = 0.75,
            McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
        });
    }
}
