// -----------------------------------------------------------------------
// <copyright file="NonPublicTargetRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Network;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-INFO-002: flags that this scan evaluated a non-public target (loopback,
/// RFC 1918 private network, link-local, or non-public DNS suffix). Transport
/// posture rules (SS-020 Critical "Insecure Transport: No TLS" in particular)
/// are exempted for such targets because an SSH tunnel or local dev port is
/// not being evaluated for production TLS. This informational finding makes
/// the exemption visible so a CI pipeline accidentally scanning localhost
/// still receives a clear signal.
/// v2.4.0 A1 / A4.
/// </summary>
public sealed class NonPublicTargetRule : IRule
{
    public string Id => RuleConstants.Rules.NonPublicTarget;
    public string Name => "Non-Public Scan Target";
    public string OwaspCode => OwaspAsiCodes.ASI03;
    public string Description =>
        "Indicates that the scanner has identified a target as non-public " +
        "(loopback, RFC 1918, link-local, or non-public hostname suffix). " +
        "Production transport posture was not evaluated for this target.";
    public bool EnabledByDefault => true;

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var config = server.ServerConfig;
            if (config.Transport is not (Core.McpProtocol.McpTransportType.Http
                or Core.McpProtocol.McpTransportType.StreamableHttp
                or Core.McpProtocol.McpTransportType.WebSocket))
            {
                continue;
            }
            if (config.Url is null)
            {
                continue;
            }

            if (!Uri.TryCreate(config.Url, UriKind.Absolute, out var uri))
            {
                continue;
            }
            var classification = NonPublicTarget.Classify(uri);
            if (!NonPublicTarget.IsNonPublic(classification))
            {
                continue;
            }

            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                Severity = Severity.Info,
                Title = $"Scan target is non-public ({NonPublicTarget.Label(classification)})",
                Description =
                    $"Server '{server.ServerName}' was scanned at a non-public URL " +
                    $"({NonPublicTarget.Label(classification)}). Production transport " +
                    "posture was not evaluated: TLS requirements (SS-020 Critical) are " +
                    "intentionally exempted because such targets are either tunneled " +
                    "(SSH / VPN) or unreachable from the public internet. If this " +
                    "target is expected to be scanned in a production posture, point the " +
                    "scanner at the public hostname instead.",
                Remediation =
                    "Intentional for local dev / tunneled scans - no action required. " +
                    "For production validation, re-scan against the public hostname so " +
                    "SS-020 and related rules evaluate the real transport posture.",
                ServerName = server.ServerName,
                Evidence = config.Url,
                Confidence = 0.95,
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
