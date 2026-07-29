// -----------------------------------------------------------------------
// <copyright file="UntrustedCertificateRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// SS-INFO-003 (v2.4.1, G3): informational rule that surfaces a finding when the
/// scanner's TLS handshake to a remote server fails specifically because of
/// certificate validation (trust chain, hostname mismatch, or expiry), rather than
/// a generic connectivity failure. Previously this was buried in the opaque
/// <c>ConnectionError</c> string; giving it its own finding lets operators tell
/// "server is unreachable" apart from "server is reachable but serving an
/// untrusted certificate" - the latter is a real security-relevant observation
/// even when the deployment intentionally uses an internal CA.
/// Maps to OWASP AST08 (Poor Scanning) in the informational sense that an opaque
/// connection error would otherwise hide a signal the scanner did observe.
/// </summary>
public sealed class UntrustedCertificateRule : IRule
{
    public string Id => RuleConstants.Rules.UntrustedServerCertificate;
    public string Name => "Untrusted Server Certificate";
    public string OwaspCode => OwaspAsiCodes.ASI10;
    public string Description =>
        "Detects remote MCP endpoints whose TLS handshake fails due to certificate " +
        "validation (untrusted issuer, hostname mismatch, or expiry) rather than a " +
        "generic connectivity failure.";
    public bool EnabledByDefault => true;
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST08];

    public Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        foreach (var server in context.Servers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (server.TlsEvidence is null)
            {
                continue;
            }

            var evidence = server.TlsEvidence;

            findings.Add(new Finding
            {
                RuleId = Id,
                OwaspCode = OwaspCode,
                AstCodes = AstCodes,
                Severity = Severity.Info,
                Title = $"Untrusted Server Certificate ({server.ServerName})",
                Description =
                    $"The TLS handshake to '{server.ServerName}' failed: {evidence.Reason}. " +
                    "This is distinct from a generic connectivity failure - the server is " +
                    "reachable but the scanner could not validate its certificate. If this " +
                    "deployment intentionally uses a private/internal CA, this finding is " +
                    "expected and can be suppressed; if the certificate should be publicly " +
                    "trusted, this indicates a misconfiguration.",
                Remediation =
                    "If the server uses a private CA, install its root certificate on " +
                    "systems that need to trust it and document the trust boundary. If the " +
                    "server should be publicly trusted, issue a certificate from a public " +
                    "CA (e.g. via ACME/Let's Encrypt) and ensure the hostname matches the " +
                    "certificate's subject/SAN.",
                ServerName = server.ServerName,
                Evidence = evidence.RawMessage ?? evidence.Reason,
                Confidence = 0.9,
                Source = FindingSource.Mcp
            });
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }
}
