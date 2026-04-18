using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class NonMcpEndpointRuleTests
{
    private static ScanContext MakeContext(params ServerEnumeration[] servers)
    {
        return new ScanContext { Servers = servers };
    }

    private static ServerEnumeration MakeServer(string name, NonMcpEndpointEvidence? evidence)
    {
        return new ServerEnumeration
        {
            ServerConfig = new McpServerConfig { Name = name, Transport = McpTransportType.Http, Url = "https://" + name },
            ServerName = name,
            Transport = "Http",
            ConnectionSuccessful = evidence is null,
            NonMcpEvidence = evidence
        };
    }

    [Fact]
    public async Task NoServers_ProducesNoFindings()
    {
        var rule = new NonMcpEndpointRule();
        var findings = await rule.EvaluateAsync(MakeContext());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task ServersWithoutEvidence_ProducesNoFindings()
    {
        var rule = new NonMcpEndpointRule();
        var context = MakeContext(MakeServer("legit-mcp", null));
        var findings = await rule.EvaluateAsync(context);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task ServerWithEvidence_ProducesInfoFinding()
    {
        var rule = new NonMcpEndpointRule();
        var context = MakeContext(MakeServer("openclaw-vucp",
            new NonMcpEndpointEvidence
            {
                ContentType = "text/html",
                BodySnippet = "<!doctype html><html><head>",
                Reason = "response body is HTML"
            }));

        var findings = (await rule.EvaluateAsync(context)).ToList();

        Assert.Single(findings);
        var f = findings[0];
        Assert.Equal("SS-INFO-001", f.RuleId);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("openclaw-vucp", f.Title, StringComparison.Ordinal);
        Assert.Contains("AST08", f.AstCodes);
        Assert.Contains("text/html", f.Evidence, StringComparison.Ordinal);
        Assert.NotNull(f.Confidence);
    }

    [Fact]
    public void DetectAndThrowIfNotMcp_HtmlContentType_Throws()
    {
        Assert.Throws<NonMcpEndpointException>(() =>
            McpConnection.DetectAndThrowIfNotMcp("text/html; charset=utf-8", "irrelevant"));
    }

    [Fact]
    public void DetectAndThrowIfNotMcp_HtmlBodyMarker_Throws()
    {
        var ex = Assert.Throws<NonMcpEndpointException>(() =>
            McpConnection.DetectAndThrowIfNotMcp(null, "<!doctype html><html/>"));
        Assert.Contains("HTML", ex.ReasonText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DetectAndThrowIfNotMcp_NonJsonBody_Throws()
    {
        Assert.Throws<NonMcpEndpointException>(() =>
            McpConnection.DetectAndThrowIfNotMcp(null, "hello world"));
    }

    [Fact]
    public void DetectAndThrowIfNotMcp_JsonBody_DoesNotThrow()
    {
        McpConnection.DetectAndThrowIfNotMcp("application/json", "{\"jsonrpc\":\"2.0\",\"result\":{}}");
    }
}
