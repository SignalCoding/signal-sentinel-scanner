// -----------------------------------------------------------------------
// <copyright file="McpLoggingCapabilityAbsentRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-INFO-007: Flags connected servers that do not advertise the MCP
/// <c>logging</c> capability. Informational (does not affect grade). Maps to
/// OWASP ASI10, MCP10 and AST08.
/// </summary>
/// <remarks>
/// Closes the MCP10 (Logging Failures) gap identified in
/// <c>_docs/ai/specs/owasp-full-coverage.md</c> C4: the scanner already parses
/// <see cref="SignalSentinel.Core.McpProtocol.McpServerCapabilities"/> for
/// <see cref="CapabilitySurfaceRule"/>, so a server whose negotiated capabilities
/// omit <c>logging</c> is a real, observable signal that its operations cannot be
/// audited through the protocol. This says nothing about whether the server keeps
/// its own logs out-of-band - the scanner cannot know that - only that the MCP
/// client has no protocol-level way to request or receive them. Modelled on
/// <see cref="CapabilitySurfaceRule"/> for structure and skip conditions.
/// </remarks>
public sealed class McpLoggingCapabilityAbsentRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.McpLoggingCapabilityAbsent;

    /// <inheritdoc />
    public string Name => "MCP Logging Capability Absent";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI10;

    /// <inheritdoc />
    public string Description =>
        "Informational notice that a connected server does not advertise the MCP " +
        "logging capability, so its operations cannot be audited through the protocol.";

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

            if (!server.ConnectionSuccessful || server.Capabilities is null)
            {
                continue;
            }

            if (server.Capabilities.Logging is not null)
            {
                continue;
            }

            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                Severity = Severity.Info,
                Title = "MCP Logging Capability Absent",
                Description =
                    $"Server '{server.ServerName}' does not advertise the MCP `logging` capability, " +
                    "so its operations cannot be audited through the protocol. This does not mean the " +
                    "server keeps no logs of its own - the scanner cannot observe that - only that a " +
                    "client cannot request or receive them via MCP.",
                Remediation =
                    "No action required. Raise it with the server operator if protocol-level audit " +
                    "logging is needed for compliance or incident response.",
                ServerName = server.ServerName,
                Confidence = 1.0,
                McpCode = OwaspMcpCodes.GetCorrespondingMcpCode(Id)
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
