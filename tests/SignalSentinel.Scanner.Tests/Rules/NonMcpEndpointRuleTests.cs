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
        var context = MakeContext(MakeServer("test-mcp-server",
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
        Assert.Contains("test-mcp-server", f.Title, StringComparison.Ordinal);
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

    [Fact]
    public void DetectAndThrowIfNotMcp_404WithNonJsonRpcJsonBody_Throws()
    {
        // v2.4.1 (G5): a REST-style 404 body that IS valid JSON but has no
        // "jsonrpc" field should still be classified as non-MCP.
        var ex = Assert.Throws<NonMcpEndpointException>(() =>
            McpConnection.DetectAndThrowIfNotMcp(
                "application/json", "{\"error\":\"not found\",\"status\":404}", statusCode: 404));
        Assert.Contains("404", ex.ReasonText, StringComparison.Ordinal);
    }

    [Fact]
    public void DetectAndThrowIfNotMcp_404WithJsonRpcErrorBody_DoesNotThrow()
    {
        // A real MCP JSON-RPC error response carries "jsonrpc" even on a 404 -
        // must not be misclassified as non-MCP.
        McpConnection.DetectAndThrowIfNotMcp(
            "application/json",
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Not Found\"},\"id\":1}",
            statusCode: 404);
    }

    [Fact]
    public async Task DetectAndThrowIfNotMcp_NonMcp404_ProducesFindingViaEnumeration()
    {
        var rule = new NonMcpEndpointRule();
        var context = MakeContext(MakeServer("rest-api-404",
            new NonMcpEndpointEvidence
            {
                ContentType = "application/json",
                BodySnippet = "{\"error\":\"not found\"}",
                Reason = "server returned HTTP 404 with a non-JSON-RPC body - no MCP protocol surface detected at this path"
            }));

        var findings = (await rule.EvaluateAsync(context)).ToList();

        Assert.Single(findings);
        Assert.Equal("SS-INFO-001", findings[0].RuleId);
    }
}
