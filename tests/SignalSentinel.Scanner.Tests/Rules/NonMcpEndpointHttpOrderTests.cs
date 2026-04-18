using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SignalSentinel.Scanner.McpClient;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

/// <summary>
/// Regression: SS-INFO-001 must surface on non-2xx responses whose body is
/// HTML or plain text (Traefik / nginx catch-all returning 404 + "Not Found").
/// Before v2.3.0 the scanner called EnsureSuccessStatusCode() before reading
/// the body, so the non-MCP heuristic never ran on 4xx responses. This test
/// locks in the correct ordering.
/// </summary>
public class NonMcpEndpointHttpOrderTests
{
    private const int MaxBytes = 10 * 1024 * 1024;

    private static HttpResponseMessage MakeResponse(HttpStatusCode status, string body, string contentType)
    {
        var response = new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, contentType)
        };
        return response;
    }

    [Fact]
    public async Task Status404_WithPlainTextBody_ThrowsNonMcp()
    {
        using var response = MakeResponse(HttpStatusCode.NotFound, "Not Found", "text/plain");

        var ex = await Assert.ThrowsAsync<NonMcpEndpointException>(() =>
            McpConnection.ReadAndInspectHttpResponseAsync(response, MaxBytes, CancellationToken.None));

        Assert.Contains("JSON", ex.ReasonText, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("text/plain", ex.ContentType);
    }

    [Fact]
    public async Task Status404_WithHtmlBody_ThrowsNonMcp()
    {
        using var response = MakeResponse(
            HttpStatusCode.NotFound,
            "<!doctype html><html><body>Not Found</body></html>",
            "text/html");

        var ex = await Assert.ThrowsAsync<NonMcpEndpointException>(() =>
            McpConnection.ReadAndInspectHttpResponseAsync(response, MaxBytes, CancellationToken.None));

        Assert.Equal("text/html", ex.ContentType);
    }

    [Fact]
    public async Task Status200_WithJsonBody_ReturnsBody()
    {
        using var response = MakeResponse(HttpStatusCode.OK, "{\"jsonrpc\":\"2.0\",\"result\":{}}", "application/json");

        var body = await McpConnection.ReadAndInspectHttpResponseAsync(response, MaxBytes, CancellationToken.None);

        Assert.Contains("jsonrpc", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Status500_WithHtmlBody_ThrowsNonMcpNotHttpException()
    {
        // Even a 500 Internal Server Error should surface SS-INFO-001 when the
        // body is clearly HTML. We must NOT see HttpRequestException here.
        using var response = MakeResponse(
            HttpStatusCode.InternalServerError,
            "<html><body>nginx error page</body></html>",
            "text/html");

        await Assert.ThrowsAsync<NonMcpEndpointException>(() =>
            McpConnection.ReadAndInspectHttpResponseAsync(response, MaxBytes, CancellationToken.None));
    }

    [Fact]
    public async Task Status500_WithJsonErrorBody_RaisesHttpExceptionAfterDetectionPasses()
    {
        // JSON-shaped 500 bodies are legitimate MCP errors; DetectAndThrowIfNotMcp
        // should pass and the HTTP status guard should then raise
        // HttpRequestException (not NonMcpEndpointException).
        using var response = MakeResponse(
            HttpStatusCode.InternalServerError,
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\"internal\"}}",
            "application/json");

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            McpConnection.ReadAndInspectHttpResponseAsync(response, MaxBytes, CancellationToken.None));
    }

    [Fact]
    public async Task ResponseTooLarge_ThrowsInvalidOperation()
    {
        var bigBody = new string('x', 1024);
        using var response = MakeResponse(HttpStatusCode.OK, bigBody, "application/json");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            McpConnection.ReadAndInspectHttpResponseAsync(response, 100, CancellationToken.None));
    }

    [Fact]
    public async Task NullResponse_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            McpConnection.ReadAndInspectHttpResponseAsync(null!, MaxBytes, CancellationToken.None));
    }
}
