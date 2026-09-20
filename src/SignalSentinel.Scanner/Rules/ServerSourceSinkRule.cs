// -----------------------------------------------------------------------
// <copyright file="ServerSourceSinkRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// v3.0.0 (WP9): SS-041. Reports dangerous sinks found by <c>--server-source</c> in files
/// that also register MCP tools. One finding per sink with <c>file:line</c> evidence.
/// Silent when no source analysis ran. Maps to OWASP ASI05.
/// </summary>
public sealed class ServerSourceSinkRule : IRule
{
    /// <inheritdoc />
    public string Id => RuleConstants.Rules.ServerSourceSink;

    /// <inheritdoc />
    public string Name => "Server Source Dangerous Sink";

    /// <inheritdoc />
    public string OwaspCode => OwaspAsiCodes.ASI05;

    /// <inheritdoc />
    public string Description =>
        "Static pass over MCP server source (--server-source): shell execution, eval, unsafe " +
        "deserialisation and home-directory writes in files that register tools.";

    /// <inheritdoc />
    public bool EnabledByDefault => true;

    /// <inheritdoc />
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST06];

    /// <inheritdoc />
    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if (context.ServerSource is not { } analysis || analysis.Sinks.Count == 0)
        {
            return Task.FromResult(Enumerable.Empty<Finding>());
        }

        var findings = analysis.Sinks
            .Select(sink => new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                Severity = sink.Severity,
                Title = $"Dangerous Sink In Tool Source: {sink.Kind} ({sink.RelativePath}:{sink.Line})",
                Description = $"{sink.Rationale} Found in '{sink.RelativePath}' line {sink.Line}, a file that registers " +
                    "MCP tools, so the call is plausibly reachable from a tool invocation the model controls.",
                Remediation =
                    "Replace shell/eval-style calls with argument-array APIs or purpose-built libraries, validate " +
                    "every tool argument against an allow-list, and keep writes inside an explicit workspace directory.",
                ServerName = analysis.DisplayName,
                ToolName = sink.RelativePath,
                Evidence = DescriptionScan.Truncate($"{sink.RelativePath}:{sink.Line}: {sink.Snippet}"),
                Confidence = 0.8
            })
            .ToList();

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
