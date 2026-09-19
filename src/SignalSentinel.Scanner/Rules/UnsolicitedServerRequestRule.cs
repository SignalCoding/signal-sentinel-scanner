// -----------------------------------------------------------------------
// <copyright file="UnsolicitedServerRequestRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-033: Flags server-to-client requests the server had no right to send.
/// Maps to OWASP ASI07 (Insecure Inter-Agent Communication).
/// </summary>
/// <remarks>
/// The scanner's <c>initialize</c> declares an empty client <c>capabilities</c> object.
/// A compliant server therefore must not send <c>sampling/createMessage</c> (ask the
/// client's model to generate text), <c>elicitation/create</c> (ask the user for input),
/// or <c>roots/list</c> (enumerate the client's filesystem roots). A server that does so
/// anyway is either non-compliant or probing whether the client enforces its own
/// declared boundaries. Sampling is Critical because it is the agentjacking primitive:
/// the server gets to author prompts the client's model will execute.
/// Other unsolicited requests are Medium; notifications are Low.
/// </remarks>
public sealed class UnsolicitedServerRequestRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.UnsolicitedServerRequest;

    /// <inheritdoc />
    public string Name => "Unsolicited Server-to-Client Request";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI07;

    /// <inheritdoc />
    public string Description =>
        "Flags sampling, elicitation, roots, or other server-initiated requests sent to a " +
        "client that declared no such capability.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST08];

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

            // Deduplicate by method so a chatty server yields one finding per method.
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var request in server.UnsolicitedRequests)
            {
                if (!seen.Add(request.Method))
                {
                    continue;
                }

                // Progress and log notifications are legitimate server-initiated traffic.
                if (IsBenignNotification(request))
                {
                    continue;
                }

                var (severity, title, description) = Classify(request);

                findings.Add(new Finding
                {
                    RuleId = Id,
                    OwaspCode = OwaspCode,
                    Severity = severity,
                    Title = title,
                    Description = description,
                    Remediation =
                        "Servers must only send sampling/elicitation/roots requests after the client has " +
                        "declared the matching capability in initialize. If this server needs those " +
                        "features, gate them on the negotiated capabilities. Clients should reject " +
                        "requests for undeclared capabilities with JSON-RPC -32601.",
                    ServerName = server.ServerName,
                    Evidence = DescriptionScan.Truncate(
                        request.ParamsSnippet is null ? request.Method : $"{request.Method} {request.ParamsSnippet}"),
                    Confidence = 0.95,
                    McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
                });
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private static bool IsBenignNotification(Core.McpProtocol.McpUnsolicitedRequest request)
    {
        if (request.IsRequest)
        {
            return false;
        }

        return request.Method.StartsWith("notifications/", StringComparison.Ordinal)
            && request.Method is "notifications/progress"
                or "notifications/message"
                or "notifications/cancelled"
                or "notifications/initialized"
                or "notifications/tools/list_changed"
                or "notifications/resources/list_changed"
                or "notifications/resources/updated"
                or "notifications/prompts/list_changed";
    }

    private static (Severity Severity, string Title, string Description) Classify(
        Core.McpProtocol.McpUnsolicitedRequest request)
    {
        var method = request.Method;

        if (method.StartsWith("sampling/", StringComparison.Ordinal))
        {
            return (Severity.Critical,
                "Server Attempted Sampling Without Client Capability",
                $"Server sent '{method}' although the client declared no sampling capability. Sampling lets the " +
                "server author prompts the client's model executes with the client's credentials and context " +
                "(agentjacking). A compliant server must not attempt this.");
        }

        if (method.StartsWith("elicitation/", StringComparison.Ordinal))
        {
            return (Severity.High,
                "Server Attempted Elicitation Without Client Capability",
                $"Server sent '{method}' although the client declared no elicitation capability. Elicitation " +
                "prompts the user for input under the server's wording, a phishing vector when unexpected.");
        }

        if (method.StartsWith("roots/", StringComparison.Ordinal))
        {
            return (Severity.High,
                "Server Attempted Roots Enumeration Without Client Capability",
                $"Server sent '{method}' although the client declared no roots capability. Roots enumeration " +
                "reveals the client's filesystem layout to the server.");
        }

        if (request.IsRequest)
        {
            return (Severity.Medium,
                "Server Sent Unexpected Request",
                $"Server sent request '{method}' which is not a standard server-to-client MCP method and " +
                "was not negotiated. Unexpected requests indicate a non-compliant or probing server.");
        }

        return (Severity.Low,
            "Server Sent Non-Standard Notification",
            $"Server sent notification '{method}' which is not a standard MCP notification.");
    }
}
