// -----------------------------------------------------------------------
// <copyright file="McpConnectionHttpTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Net;
using System.Text;
using System.Text.Json;
using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Offline;
using Xunit;

namespace SignalSentinel.Scanner.Tests;

/// <summary>
/// v3.0.0 smoke-fix regressions for the Streamable HTTP client (D1, D3, D7), driven
/// against a loopback <see cref="HttpListener"/> so no network egress is needed.
/// Shares the offline-guard collection because it must run with the guard disabled.
/// </summary>
[Collection("OfflineGuardSerial")]
public sealed class McpConnectionHttpTests
{
    private const string SessionId = "sess-12345";

    [Fact]
    public async Task InitializedNotification_CarriesSessionId_AndClientRequestsCurrentVersion()
    {
        OfflineGuard.Reset();

        var seen = new List<(string Method, string? Session, string Body)>();
        using var server = new FakeStreamableHttpServer(async ctx =>
        {
            var body = await ReadBody(ctx).ConfigureAwait(true);
            var method = MethodOf(body);
            seen.Add((method, ctx.Request.Headers["Mcp-Session-Id"], body));

            switch (method)
            {
                case "initialize":
                    ctx.Response.Headers["Mcp-Session-Id"] = SessionId;
                    await WriteJson(ctx.Response, """{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"1"}}}""").ConfigureAwait(true);
                    break;
                case "notifications/initialized":
                    ctx.Response.StatusCode = 202;
                    ctx.Response.Close();
                    break;
                default:
                    if (ctx.Request.Headers["Mcp-Session-Id"] != SessionId)
                    {
                        await WriteJson(ctx.Response, """{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"Session not initialized"}}""").ConfigureAwait(true);
                        break;
                    }

                    await WriteJson(ctx.Response, """{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"ping","description":"Pong."}]}}""").ConfigureAwait(true);
                    break;
            }
        });

        var connection = Connect("fake", server.Url);
        await using (connection.ConfigureAwait(true))
        {
            var init = await connection.ConnectAsync().ConfigureAwait(true);
            var tools = await connection.ListToolsAsync().ConfigureAwait(true);

            init.ProtocolVersion.ShouldBe("2025-06-18");
            tools.Tools.ShouldHaveSingleItem().Name.ShouldBe("ping");
        }

        seen.Select(s => s.Method).ShouldBe(["initialize", "notifications/initialized", "tools/list"]);
        seen[0].Body.ShouldContain($"\"protocolVersion\":\"{McpProtocolVersions.Current}\"");
        seen[1].Session.ShouldBe(SessionId, "notifications/initialized must carry the session id");
        seen[2].Session.ShouldBe(SessionId);
    }

    [Fact]
    public async Task Initialize_RetriesWithFallback_WhenServerRejectsCurrentVersion()
    {
        OfflineGuard.Reset();

        var requested = new List<string>();
        using var server = new FakeStreamableHttpServer(async ctx =>
        {
            var body = await ReadBody(ctx).ConfigureAwait(true);
            if (MethodOf(body) != "initialize")
            {
                ctx.Response.StatusCode = 202;
                ctx.Response.Close();
                return;
            }

            using var doc = JsonDocument.Parse(body);
            var version = doc.RootElement.GetProperty("params").GetProperty("protocolVersion").GetString() ?? string.Empty;
            requested.Add(version);
            if (version == McpProtocolVersions.Current)
            {
                await WriteJson(ctx.Response, """{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unsupported protocol version"}}""").ConfigureAwait(true);
                return;
            }

            await WriteJson(ctx.Response, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":\"" + version + "\",\"capabilities\":{},\"serverInfo\":{\"name\":\"strict\",\"version\":\"1\"}}}").ConfigureAwait(true);
        });

        var connection = Connect("strict", server.Url);
        await using (connection.ConfigureAwait(true))
        {
            var init = await connection.ConnectAsync().ConfigureAwait(true);
            init.ProtocolVersion.ShouldBe(McpProtocolVersions.Fallback);
        }

        requested.ShouldBe([McpProtocolVersions.Current, McpProtocolVersions.Fallback]);
    }

    [Fact]
    public async Task LegacySseEndpoint_ThrowsLegacySseEndpointException()
    {
        OfflineGuard.Reset();

        using var server = new FakeStreamableHttpServer(async ctx =>
        {
            if (ctx.Request.HttpMethod == "GET")
            {
                await WriteRaw(ctx.Response, 200, "text/event-stream", "event: endpoint\ndata: /messages/?session_id=abc\n\n").ConfigureAwait(true);
                return;
            }

            await WriteRaw(ctx.Response, 405, "text/plain", "Method Not Allowed").ConfigureAwait(true);
        });

        var connection = Connect("sse", server.Url);
        await using (connection.ConfigureAwait(true))
        {
            var ex = await Should.ThrowAsync<LegacySseEndpointException>(() => connection.ConnectAsync()).ConfigureAwait(true);
            ex.PostStatusCode.ShouldBe(405);
        }
    }

    [Fact]
    public async Task PlainTextEndpoint_WithoutSseOnGet_IsStillNonMcp()
    {
        OfflineGuard.Reset();

        using var server = new FakeStreamableHttpServer(ctx =>
            WriteRaw(ctx.Response, ctx.Request.HttpMethod == "GET" ? 200 : 405, "text/html", "<html><body>Not an MCP server</body></html>"));

        var connection = Connect("web", server.Url);
        await using (connection.ConfigureAwait(true))
        {
            await Should.ThrowAsync<NonMcpEndpointException>(() => connection.ConnectAsync()).ConfigureAwait(true);
        }
    }

    // ---- helpers -------------------------------------------------------------------

    private static McpConnection Connect(string name, string url) => new(
        new McpServerConfig { Name = name, Transport = McpTransportType.StreamableHttp, Url = url },
        TimeSpan.FromSeconds(10));

    private static async Task<string> ReadBody(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream);
        return await reader.ReadToEndAsync().ConfigureAwait(true);
    }

    private static string MethodOf(string body)
    {
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("method").GetString() ?? string.Empty;
    }

    private static Task WriteJson(HttpListenerResponse response, string json) =>
        WriteRaw(response, 200, "application/json", json);

    private static async Task WriteRaw(HttpListenerResponse response, int status, string contentType, string body)
    {
        response.StatusCode = status;
        response.ContentType = contentType;
        var bytes = Encoding.UTF8.GetBytes(body);
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes).ConfigureAwait(true);
        response.Close();
    }

    /// <summary>
    /// Minimal loopback HTTP server: one handler for every request, random free port.
    /// </summary>
    private sealed class FakeStreamableHttpServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly CancellationTokenSource _cts = new();

        public string Url { get; }

        public FakeStreamableHttpServer(Func<HttpListenerContext, Task> handler)
        {
            var port = FreePort();
            Url = $"http://127.0.0.1:{port}/mcp";
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            _listener.Start();
            _ = Task.Run(() => LoopAsync(handler));
        }

        private async Task LoopAsync(Func<HttpListenerContext, Task> handler)
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (HttpListenerException) when (_cts.IsCancellationRequested)
                {
                    return;
                }
                catch (ObjectDisposedException) when (_cts.IsCancellationRequested)
                {
                    return;
                }

                try
                {
                    await handler(ctx).ConfigureAwait(false);
                }
                catch (IOException)
                {
                    ctx.Response.Abort();
                }
                catch (HttpListenerException)
                {
                    ctx.Response.Abort();
                }
            }
        }

        private static int FreePort()
        {
            using var socket = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            socket.Start();
            var port = ((IPEndPoint)socket.LocalEndpoint).Port;
            socket.Stop();
            return port;
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Close();
            _cts.Dispose();
        }
    }
}
