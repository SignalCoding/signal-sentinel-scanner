// -----------------------------------------------------------------------
// <copyright file="UntrustedCertificateRuleTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class UntrustedCertificateRuleTests
{
    private readonly UntrustedCertificateRule _rule = new();

    private static ScanContext MakeContext(TlsErrorEvidence? evidence)
    {
        return new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig { Name = "server", Transport = McpTransportType.Http, Url = "https://server" },
                    ServerName = "server",
                    Transport = "Http",
                    ConnectionSuccessful = evidence is null,
                    TlsEvidence = evidence
                }
            ]
        };
    }

    [Fact]
    public async Task Evaluate_NoTlsEvidence_ProducesNoFindings()
    {
        var findings = await _rule.EvaluateAsync(MakeContext(null));
        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task Evaluate_WithTlsEvidence_ProducesInfoFinding()
    {
        var context = MakeContext(new TlsErrorEvidence
        {
            Reason = "certificate validation failed",
            RawMessage = "The remote certificate is invalid according to the validation procedure."
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].RuleId.ShouldBe("SS-INFO-003");
        findings[0].Severity.ShouldBe(Severity.Info);
        findings[0].AstCodes.ShouldContain("AST08");
        findings[0].ServerName.ShouldBe("server");
    }
}
