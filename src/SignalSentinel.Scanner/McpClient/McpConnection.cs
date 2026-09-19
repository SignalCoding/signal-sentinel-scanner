using System.Diagnostics;
using System.Net.WebSockets;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Scanner.Offline;

namespace SignalSentinel.Scanner.McpClient;

/// <summary>
/// Manages connections to MCP servers via stdio, HTTP, or WebSocket transport.
/// Security hardened for production use.
/// </summary>
public sealed class McpConnection : IAsyncDisposable
{
    private readonly McpServerConfig _config;
    private readonly TimeSpan _timeout;
    private Process? _process;
    private HttpClient? _httpClient;
    private string? _mcpSessionId;
    private ClientWebSocket? _webSocket;
    private int _requestId;
    private bool _disposed;

    // v3.0.0: server-initiated messages and error bodies observed during the session.
    // Bounded so a hostile server cannot grow these without limit.
    private readonly List<McpUnsolicitedRequest> _unsolicited = [];
    private readonly List<McpProtocolError> _protocolErrors = [];
    private const int MaxRecordedUnsolicited = 50;
    private const int MaxRecordedErrors = 50;
    private const int MaxParamsSnippetLength = 200;
    private const int MaxErrorMessageLength = 500;

    // Security: Limit response sizes to prevent memory exhaustion
    private const int MaxResponseSizeBytes = 10 * 1024 * 1024; // 10MB
    private const int WebSocketReceiveBufferSize = 8192;

    private static readonly string UserAgentString = $"SignalSentinel.Scanner/{typeof(McpConnection).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        MaxDepth = 32 // Prevent deeply nested JSON attacks
    };

    public McpConnection(McpServerConfig config, TimeSpan timeout)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _timeout = timeout;

        // Security: Enforce reasonable timeout bounds
        if (_timeout < TimeSpan.FromSeconds(1))
            _timeout = TimeSpan.FromSeconds(1);
        if (_timeout > TimeSpan.FromMinutes(5))
            _timeout = TimeSpan.FromMinutes(5);
    }

    /// <summary>
    /// Gets the server configuration.
    /// </summary>
    public McpServerConfig Config => _config;

    /// <summary>
    /// v3.0.0: server-to-client requests and notifications received while this
    /// connection was awaiting its own responses. The scanner declares no client
    /// capabilities during <c>initialize</c>, so any <c>sampling/*</c>,
    /// <c>elicitation/*</c>, or <c>roots/*</c> request here is a protocol violation.
    /// </summary>
    public IReadOnlyList<McpUnsolicitedRequest> UnsolicitedRequests => _unsolicited;

    /// <summary>
    /// v3.0.0: JSON-RPC error objects the server returned for the scanner's requests.
    /// </summary>
    public IReadOnlyList<McpProtocolError> ProtocolErrors => _protocolErrors;

    /// <summary>
    /// Opens the connection to the MCP server.
    /// </summary>
    public async Task<McpInitializeResult> ConnectAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_config.Transport == McpTransportType.Stdio)
        {
            await StartProcessAsync(cancellationToken);
        }
        else if (_config.Transport == McpTransportType.WebSocket)
        {
            OfflineGuard.EnsureAllowed($"WebSocket connect to {_config.Url}");
            await ConnectWebSocketAsync(cancellationToken);
        }
        else
        {
            OfflineGuard.EnsureAllowed($"HTTP connect to {_config.Url}");

            // Security: Configure HttpClient with security settings
            var handler = new HttpClientHandler
            {
                // Security: Enable certificate revocation list checking
                CheckCertificateRevocationList = true,
                // Security: Enforce modern TLS versions only (intentional hardcoding)
#pragma warning disable CA5398 // Intentionally restricting to TLS 1.2+ for security
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
#pragma warning restore CA5398
            };

            _httpClient = new HttpClient(handler)
            {
                Timeout = _timeout,
                MaxResponseContentBufferSize = MaxResponseSizeBytes
            };

            // Security: Add user agent for identification
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgentString);

            // MCP 2025-06-18 Streamable HTTP transport requires clients to accept
            // both JSON responses and SSE streams. Omitting these caused 406 from
            // spec-compliant servers (e.g. ModelContextProtocol.AspNetCore).
            _httpClient.DefaultRequestHeaders.Accept.ParseAdd("application/json");
            _httpClient.DefaultRequestHeaders.Accept.ParseAdd("text/event-stream");

            // Apply operator-supplied custom headers (e.g. Authorization: Bearer).
            // Sensitive; never logged. CRLF/control chars filtered at config-parse time.
            if (_config.Headers is not null)
            {
                foreach (var kv in _config.Headers)
                {
                    // TryAddWithoutValidation permits Authorization + other typically-restricted headers.
                    _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(kv.Key, kv.Value);
                }
            }
        }

        return await InitializeAsync(cancellationToken);
    }

    /// <summary>
    /// Lists all tools available on the server.
    /// </summary>
    public async Task<McpToolsListResult> ListToolsAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var result = await SendRequestAsync<McpToolsListResult>("tools/list", null, cancellationToken);
        return result ?? new McpToolsListResult { Tools = [] };
    }

    /// <summary>
    /// Lists all resources available on the server.
    /// </summary>
    public async Task<McpResourcesListResult> ListResourcesAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var result = await SendRequestAsync<McpResourcesListResult>("resources/list", null, cancellationToken);
        return result ?? new McpResourcesListResult { Resources = [] };
    }

    /// <summary>
    /// Lists all prompts available on the server.
    /// </summary>
    public async Task<McpPromptsListResult> ListPromptsAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var result = await SendRequestAsync<McpPromptsListResult>("prompts/list", null, cancellationToken);
        return result ?? new McpPromptsListResult { Prompts = [] };
    }

    private async Task ConnectWebSocketAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(_config.Url))
        {
            throw new InvalidOperationException($"No URL specified for WebSocket transport on server '{_config.Name}'");
        }

        // Security: Validate and convert URL to WebSocket scheme
        var wsUri = GetWebSocketUri(_config.Url);

        _webSocket = new ClientWebSocket();

        // Security: Set reasonable buffer sizes
        _webSocket.Options.SetBuffer(WebSocketReceiveBufferSize, WebSocketReceiveBufferSize);

        // Security: Set user agent
        _webSocket.Options.SetRequestHeader("User-Agent", UserAgentString);

        // Apply operator-supplied custom headers (e.g. Authorization: Bearer).
        if (_config.Headers is not null)
        {
            foreach (var kv in _config.Headers)
            {
                _webSocket.Options.SetRequestHeader(kv.Key, kv.Value);
            }
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_timeout);

        try
        {
            await _webSocket.ConnectAsync(wsUri, cts.Token);
        }
        catch (WebSocketException ex)
        {
            throw new InvalidOperationException(
                $"Failed to connect WebSocket to '{_config.Name}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Converts an HTTP/WS URL to a valid WebSocket URI.
    /// </summary>
    private static Uri GetWebSocketUri(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"Invalid WebSocket URL: {url}");
        }

        // Security: Only allow ws, wss, http, https schemes
        var scheme = uri.Scheme.ToLowerInvariant() switch
        {
            "ws" => "ws",
            "wss" => "wss",
            "http" => "ws",
            "https" => "wss",
            _ => throw new InvalidOperationException(
                $"Unsupported scheme '{uri.Scheme}' for WebSocket transport. Use ws://, wss://, http://, or https://")
        };

        var builder = new UriBuilder(uri) { Scheme = scheme };
        return builder.Uri;
    }

    /// <summary>
    /// v2.3.0: classifies the first HTTP response from an alleged MCP endpoint.
    /// Reads the body of an <see cref="HttpResponseMessage"/>, applies the non-MCP
    /// endpoint detector, and only then validates the HTTP status code. The ordering
    /// is deliberate: a React SPA hosted on a Traefik/nginx catch-all typically
    /// returns 404 on POST to /mcp while its body still identifies the endpoint as
    /// non-MCP (HTML / plain-text "Not Found"). Running the detector first ensures
    /// SS-INFO-001 fires instead of an opaque HTTP 404 error.
    /// </summary>
    internal static async Task<string> ReadAndInspectHttpResponseAsync(
        HttpResponseMessage response,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        var frames = await ReadAndInspectHttpFramesAsync(response, maxBytes, cancellationToken);
        return frames[0];
    }

    /// <summary>
    /// As <see cref="ReadAndInspectHttpResponseAsync"/> but returns every JSON frame in
    /// the body. A plain JSON body yields one frame; an SSE body yields one frame per
    /// event, in order, so callers can pick out server-initiated messages that arrived
    /// ahead of the actual response. Always returns at least one element.
    /// </summary>
    internal static async Task<IReadOnlyList<string>> ReadAndInspectHttpFramesAsync(
        HttpResponseMessage response,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);

        if (response.Content.Headers.ContentLength > maxBytes)
        {
            throw new InvalidOperationException("Response too large");
        }

        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (body.Length > maxBytes)
        {
            throw new InvalidOperationException("Response too large");
        }

        var contentType = response.Content.Headers.ContentType?.MediaType;

        // MCP 2025-06-18 Streamable HTTP transport responds either with
        // application/json (immediate) or text/event-stream (SSE framed).
        // Unwrap SSE framing into raw JSON so callers see a uniform payload.
        IReadOnlyList<string> frames = [body];
        if (!string.IsNullOrEmpty(contentType) &&
            contentType.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase))
        {
            var split = SplitServerSentEvents(body);
            if (split.Count > 0)
            {
                frames = split;
            }
        }

        DetectAndThrowIfNotMcp(contentType, frames[0], (int)response.StatusCode);

        response.EnsureSuccessStatusCode();

        return frames;
    }

    /// <summary>
    /// Extracts the JSON payload from a minimal Server-Sent Events stream
    /// produced by MCP Streamable HTTP transports. Concatenates all
    /// <c>data:</c> lines belonging to the first message (per SSE spec,
    /// multi-line data values are joined with newlines).
    /// </summary>
    internal static string ExtractJsonFromServerSentEvents(string body)
    {
        if (string.IsNullOrEmpty(body))
        {
            return body;
        }

        var frames = SplitServerSentEvents(body);
        return frames.Count == 0 ? body : frames[0];
    }

    /// <summary>
    /// Splits a Server-Sent Events body into the <c>data</c> payload of each event, in
    /// order. Events with no <c>data:</c> line are dropped. Returns an empty list when
    /// the body contains no SSE data at all.
    /// </summary>
    internal static IReadOnlyList<string> SplitServerSentEvents(string body)
    {
        if (string.IsNullOrEmpty(body))
        {
            return [];
        }

        var frames = new List<string>();
        var dataParts = new List<string>();

        void Flush()
        {
            if (dataParts.Count > 0)
            {
                frames.Add(string.Join("\n", dataParts));
                dataParts.Clear();
            }
        }

        foreach (var rawLine in body.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            // Blank line terminates the current SSE event.
            if (string.IsNullOrEmpty(line))
            {
                Flush();
                continue;
            }
            if (line.StartsWith("data:", StringComparison.Ordinal))
            {
                // Per SSE spec, a single leading space after the colon is stripped.
                var payload = line.Length > 5 && line[5] == ' ' ? line[6..] : line[5..];
                dataParts.Add(payload);
            }
            // Ignore event:, id:, retry:, comments, etc.
        }

        Flush();
        return frames;
    }

    /// <summary>
    /// Throws <see cref="NonMcpEndpointException"/> when the response is clearly
    /// not a JSON-RPC 2.0 payload (e.g. React SPA catch-all serving text/html).
    /// </summary>
    /// <param name="contentType">Response Content-Type header value, if any.</param>
    /// <param name="responseBody">Response body, already size-checked by the caller.</param>
    /// <param name="statusCode">
    /// v2.4.1 (G5): HTTP status code of the response. Used only by the 404 heuristic
    /// below; pass 0 (or any non-404 value) when the status code is not relevant.
    /// </param>
    internal static void DetectAndThrowIfNotMcp(string? contentType, string responseBody, int statusCode = 0)
    {
        var snippet = BuildSnippet(responseBody);

        // Heuristic 1: Content-Type is text/html or similar.
        if (!string.IsNullOrEmpty(contentType))
        {
            var lower = contentType.ToLowerInvariant();
            if (lower.Contains("text/html", StringComparison.Ordinal) ||
                lower.Contains("application/xhtml+xml", StringComparison.Ordinal))
            {
                throw new NonMcpEndpointException(
                    $"server returned {contentType}, not JSON-RPC",
                    contentType,
                    snippet);
            }
        }

        // Heuristic 2: Response body begins with HTML markers.
        if (!string.IsNullOrEmpty(responseBody))
        {
            var trimmed = responseBody.TrimStart();
            if (trimmed.StartsWith("<!doctype", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("<html", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("<body", StringComparison.OrdinalIgnoreCase))
            {
                throw new NonMcpEndpointException(
                    "response body is HTML, not JSON-RPC",
                    contentType,
                    snippet);
            }
        }

        // Heuristic 3: Response does not look like JSON at all.
        if (!string.IsNullOrEmpty(responseBody))
        {
            var firstNonWhitespace = responseBody.TrimStart().FirstOrDefault();
            if (firstNonWhitespace != '{' && firstNonWhitespace != '[')
            {
                throw new NonMcpEndpointException(
                    "response body is not JSON",
                    contentType,
                    snippet);
            }
        }

        // v2.4.1 (G5): heuristic 4 - HTTP 404 with a body that IS valid JSON but is
        // not JSON-RPC shaped (e.g. a REST-style "{"error":"not found"}" body). A
        // real MCP server's JSON-RPC error responses always carry a "jsonrpc" field
        // per spec (including error responses), so this cannot misclassify a
        // legitimate MCP error as non-MCP. Previously this case fell through to
        // response.EnsureSuccessStatusCode() and surfaced as an opaque HTTP 404
        // ConnectionError with no finding explaining why - see BACKLOG_V2.4.1 G5.
        if (statusCode == 404 && !LooksLikeJsonRpc(responseBody))
        {
            throw new NonMcpEndpointException(
                "server returned HTTP 404 with a non-JSON-RPC body - no MCP protocol surface detected at this path",
                contentType,
                snippet);
        }
    }

    /// <summary>
    /// v2.4.1 (G5): true when the body contains the <c>"jsonrpc"</c> field that every
    /// JSON-RPC 2.0 message (request, response, or error) is required to carry.
    /// </summary>
    private static bool LooksLikeJsonRpc(string responseBody) =>
        !string.IsNullOrEmpty(responseBody) &&
        responseBody.Contains("\"jsonrpc\"", StringComparison.Ordinal);

    private static string? BuildSnippet(string? body)
    {
        if (string.IsNullOrEmpty(body))
        {
            return null;
        }
        var snippet = body.Length <= 200 ? body : body[..200];
        // Collapse control characters for safe display.
        var chars = snippet
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ');
        return new string([.. chars.Where(c => !char.IsControl(c))]);
    }

    private async Task StartProcessAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(_config.Command))
        {
            throw new InvalidOperationException($"No command specified for stdio transport on server '{_config.Name}'");
        }

        // Security: Validate command is not obviously malicious
        ValidateCommand(_config.Command);

        var startInfo = new ProcessStartInfo
        {
            FileName = _config.Command,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            // Security: Don't inherit environment by default in sensitive scenarios
        };

        if (_config.Args is not null)
        {
            foreach (var arg in _config.Args)
            {
                // Security: Basic validation of arguments
                if (!string.IsNullOrWhiteSpace(arg))
                {
                    startInfo.ArgumentList.Add(arg);
                }
            }
        }

        if (_config.Env is not null)
        {
            // Security: Denylist of sensitive environment variables that must not be overridden
            var envDenylist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH",
                "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
                "PYTHONPATH", "NODE_PATH",
                "COMSPEC", "SHELL", "HOME", "USERPROFILE",
                "SystemRoot", "windir"
            };

            foreach (var (key, value) in _config.Env)
            {
                // Security: Only set non-empty environment variables, skip denylisted keys
                if (!string.IsNullOrWhiteSpace(key) && value is not null)
                {
                    if (envDenylist.Contains(key))
                    {
                        continue;
                    }
                    startInfo.Environment[key] = value;
                }
            }
        }

        _process = new Process
        {
            StartInfo = startInfo,         // Security: Enable process exited event for cleanup
            EnableRaisingEvents = true
        };

        if (!_process.Start())
        {
            throw new InvalidOperationException($"Failed to start MCP server process for '{_config.Name}'");
        }

        // Give the process a moment to start
        await Task.Delay(100, cancellationToken);

        if (_process.HasExited)
        {
            var stderr = await _process.StandardError.ReadToEndAsync(cancellationToken);
            // Security: Truncate error output to prevent log flooding
            if (stderr.Length > 1000)
            {
                stderr = stderr[..1000] + "... (truncated)";
            }
            throw new InvalidOperationException(
                $"MCP server process for '{_config.Name}' exited immediately. Error: {stderr}");
        }
    }

    private static void ValidateCommand(string command)
    {
        // Security: Block obviously dangerous commands
        var dangerous = new[] { "rm ", "del ", "format ", "mkfs", "> /dev", "| bash", "| sh", "&& rm" };
        var lowerCmd = command.ToLowerInvariant();

        foreach (var pattern in dangerous)
        {
            if (lowerCmd.Contains(pattern))
            {
                throw new InvalidOperationException(
                    $"Command contains potentially dangerous pattern: {pattern}");
            }
        }
    }

    private async Task<McpInitializeResult> InitializeAsync(CancellationToken cancellationToken)
    {
        var initParams = new
        {
            protocolVersion = "2024-11-05",
            capabilities = new { },
            clientInfo = new
            {
                name = "SignalSentinel.Scanner",
                version = typeof(McpConnection).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"
            }
        };

        var result = await SendRequestAsync<McpInitializeResult>("initialize", initParams, cancellationToken) ?? throw new InvalidOperationException($"Failed to initialize MCP server '{_config.Name}'");

        // Send initialized notification
        await SendNotificationAsync("notifications/initialized", null, cancellationToken);

        return result;
    }

    private async Task<TResult?> SendRequestAsync<TResult>(
        string method,
        object? @params,
        CancellationToken cancellationToken) where TResult : class
    {
        var id = Interlocked.Increment(ref _requestId);
        var request = new JsonRpcRequest
        {
            Id = id,
            Method = method,
            Params = @params
        };

        var requestJson = JsonSerializer.Serialize(request, JsonOptions);

        // Security: Limit request size
        if (requestJson.Length > 1_000_000)
        {
            throw new InvalidOperationException("Request too large");
        }

        if (_config.Transport == McpTransportType.Stdio)
        {
            return await SendStdioRequestAsync<TResult>(method, requestJson, id, cancellationToken);
        }
        else if (_config.Transport == McpTransportType.WebSocket)
        {
            return await SendWebSocketRequestAsync<TResult>(method, requestJson, id, cancellationToken);
        }
        else
        {
            return await SendHttpRequestAsync<TResult>(method, requestJson, cancellationToken);
        }
    }

    private async Task SendNotificationAsync(string method, object? @params, CancellationToken cancellationToken)
    {
        var notification = new JsonRpcNotification
        {
            Method = method,
            Params = @params
        };

        var json = JsonSerializer.Serialize(notification, JsonOptions);

        if (_config.Transport == McpTransportType.Stdio)
        {
            if (_process?.StandardInput is not null)
            {
                await _process.StandardInput.WriteLineAsync(json.AsMemory(), cancellationToken);
                await _process.StandardInput.FlushAsync(cancellationToken);
            }
        }
        else if (_config.Transport == McpTransportType.WebSocket)
        {
            if (_webSocket is not null && _webSocket.State == WebSocketState.Open)
            {
                var bytes = Encoding.UTF8.GetBytes(json);
                await _webSocket.SendAsync(bytes.AsMemory(), WebSocketMessageType.Text, true, cancellationToken);
            }
        }
        else if (_httpClient is not null && _config.Url is not null)
        {
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            await _httpClient.PostAsync(new Uri(_config.Url), content, cancellationToken);
        }
    }

    private async Task<TResult?> SendStdioRequestAsync<TResult>(
        string method,
        string requestJson,
        int expectedId,
        CancellationToken cancellationToken) where TResult : class
    {
        if (_process is null)
        {
            throw new InvalidOperationException("Process not started");
        }

        await _process.StandardInput.WriteLineAsync(requestJson.AsMemory(), cancellationToken);
        await _process.StandardInput.FlushAsync(cancellationToken);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_timeout);

        var totalBytesRead = 0;

        while (!cts.Token.IsCancellationRequested)
        {
            var line = await ReadBoundedLineAsync(_process.StandardOutput, MaxResponseSizeBytes, cts.Token);
            if (string.IsNullOrEmpty(line))
            {
                continue;
            }

            // Security: Track total bytes read to prevent memory exhaustion
            totalBytesRead += line.Length;
            if (totalBytesRead > MaxResponseSizeBytes)
            {
                throw new InvalidOperationException("Response too large - possible denial of service");
            }

            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;

                // v3.0.0: a message with "method" is server-initiated (request or
                // notification), never a response to us. Record it and, if it expects a
                // reply, decline so the session stays well-formed.
                if (root.TryGetProperty("method", out _))
                {
                    var declineJson = RecordUnsolicited(root);
                    if (declineJson is not null)
                    {
                        // Best effort: a server that closed stdin right after asking us
                        // something should not abort enumeration of what we already have.
                        try
                        {
                            await _process.StandardInput.WriteLineAsync(declineJson.AsMemory(), cts.Token);
                            await _process.StandardInput.FlushAsync(cts.Token);
                        }
                        catch (IOException)
                        {
                            // Swallowed by design; see comment above.
                        }
                        catch (ObjectDisposedException)
                        {
                            // Swallowed by design; see comment above.
                        }
                    }
                    continue;
                }

                // Check if this is a response (has id)
                if (root.TryGetProperty("id", out var idElement))
                {
                    var responseId = idElement.ValueKind switch
                    {
                        JsonValueKind.Number => idElement.GetInt32(),
                        JsonValueKind.String => int.TryParse(idElement.GetString(), out var parsed) ? parsed : -1,
                        _ => -1
                    };

                    if (responseId == expectedId)
                    {
                        if (root.TryGetProperty("error", out var error))
                        {
                            var errorMsg = RecordProtocolError(method, error);
                            throw new InvalidOperationException($"MCP error: {errorMsg}");
                        }

                        if (root.TryGetProperty("result", out var result))
                        {
                            return JsonSerializer.Deserialize<TResult>(result.GetRawText(), JsonOptions);
                        }

                        return null;
                    }
                }
            }
            catch (JsonException)
            {
                // Not valid JSON, skip
            }
        }

        throw new TimeoutException($"Timeout waiting for response from MCP server '{_config.Name}'");
    }

    /// <summary>
    /// Records a server-initiated message. Returns a JSON-RPC "method not found" error
    /// response to send back when the message was a request (had an <c>id</c>), or null
    /// for notifications.
    /// </summary>
    private string? RecordUnsolicited(JsonElement root)
    {
        var (record, declineJson) = ParseUnsolicited(root);
        if (_unsolicited.Count < MaxRecordedUnsolicited)
        {
            _unsolicited.Add(record);
        }
        return declineJson;
    }

    /// <summary>
    /// Pure parser for a server-initiated message: builds the evidence record and, for
    /// requests (messages with an <c>id</c>), the JSON-RPC -32601 decline to send back.
    /// </summary>
    internal static (McpUnsolicitedRequest Record, string? DeclineJson) ParseUnsolicited(JsonElement root)
    {
        var methodName = root.TryGetProperty("method", out var m) && m.ValueKind == JsonValueKind.String
            ? m.GetString() ?? "(unknown)"
            : "(unknown)";
        methodName = StripControl(methodName, 128);

        var hasId = root.TryGetProperty("id", out var idEl) && idEl.ValueKind != JsonValueKind.Null;

        string? snippet = null;
        if (root.TryGetProperty("params", out var p))
        {
            snippet = StripControl(p.GetRawText(), MaxParamsSnippetLength);
        }

        var record = new McpUnsolicitedRequest
        {
            Method = methodName,
            IsRequest = hasId,
            ParamsSnippet = snippet
        };

        if (!hasId)
        {
            return (record, null);
        }

        // Echo the id back unchanged (number or string) so the server can correlate.
        var decline = new
        {
            jsonrpc = "2.0",
            id = idEl,
            error = new { code = -32601, message = "Method not found" }
        };
        return (record, JsonSerializer.Serialize(decline, JsonOptions));
    }

    /// <summary>
    /// Records a JSON-RPC error object for a request the scanner sent and returns the
    /// sanitised message for the thrown exception.
    /// </summary>
    private string RecordProtocolError(string method, JsonElement error)
    {
        var record = ParseProtocolError(method, error);
        if (_protocolErrors.Count < MaxRecordedErrors)
        {
            _protocolErrors.Add(record);
        }
        return record.Message;
    }

    /// <summary>
    /// Pure parser for a JSON-RPC error object: sanitised, bounded message plus code.
    /// </summary>
    internal static McpProtocolError ParseProtocolError(string method, JsonElement error)
    {
        var errorMsg = error.TryGetProperty("message", out var msgEl) && msgEl.ValueKind == JsonValueKind.String
            ? msgEl.GetString() ?? "Unknown error"
            : "Unknown error";
        errorMsg = StripControl(errorMsg, MaxErrorMessageLength);

        var code = error.TryGetProperty("code", out var codeEl) && codeEl.ValueKind == JsonValueKind.Number
            && codeEl.TryGetInt32(out var c) ? c : 0;

        return new McpProtocolError { Method = method, Code = code, Message = errorMsg };
    }

    private static string StripControl(string input, int maxLength)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(Math.Min(input.Length, maxLength));
        foreach (var ch in input)
        {
            if (sb.Length >= maxLength)
            {
                sb.Append("...");
                break;
            }
            if (!char.IsControl(ch) || ch == ' ')
            {
                sb.Append(ch);
            }
        }
        return sb.ToString();
    }

    private async Task<TResult?> SendHttpRequestAsync<TResult>(
        string method,
        string requestJson,
        CancellationToken cancellationToken) where TResult : class
    {
        if (_httpClient is null || string.IsNullOrEmpty(_config.Url))
        {
            throw new InvalidOperationException("HTTP client not configured");
        }

        // Security: Validate URL
        if (!Uri.TryCreate(_config.Url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != "http" && uri.Scheme != "https"))
        {
            throw new InvalidOperationException($"Invalid URL: {_config.Url}");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new StringContent(requestJson, Encoding.UTF8, "application/json")
        };

        // MCP 2025-06-18 Streamable HTTP transport: once the server has issued
        // an Mcp-Session-Id during initialize, every subsequent request must
        // carry it; otherwise the server answers 400 Bad Request.
        if (!string.IsNullOrEmpty(_mcpSessionId))
        {
            request.Headers.TryAddWithoutValidation("Mcp-Session-Id", _mcpSessionId);
        }

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        // Capture any session id issued by this response (initialize, or server-refreshed).
        if (response.Headers.TryGetValues("Mcp-Session-Id", out var sidValues))
        {
            var sid = sidValues.FirstOrDefault();
            if (!string.IsNullOrEmpty(sid) && sid.Length <= 256 && !sid.Any(char.IsControl))
            {
                _mcpSessionId = sid;
            }
        }

        var frames = await ReadAndInspectHttpFramesAsync(response, MaxResponseSizeBytes, cancellationToken);

        // An SSE body may carry server-initiated messages (log notifications, sampling
        // requests) ahead of the actual response. Record those and answer from the
        // first frame that is a response. Over HTTP a decline would be a separate POST,
        // which we deliberately do not send; the record is what the rules need.
        JsonException? lastParseError = null;
        var parsedAny = false;
        foreach (var frame in frames)
        {
            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(frame);
            }
            catch (JsonException ex)
            {
                lastParseError = ex;
                continue;
            }

            parsedAny = true;
            using (doc)
            {
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                if (root.TryGetProperty("method", out _))
                {
                    RecordUnsolicited(root);
                    continue;
                }

                if (root.TryGetProperty("error", out var error))
                {
                    var errorMsg = RecordProtocolError(method, error);
                    throw new InvalidOperationException($"MCP error: {errorMsg}");
                }

                if (root.TryGetProperty("result", out var result))
                {
                    return JsonSerializer.Deserialize<TResult>(result.GetRawText(), JsonOptions);
                }
            }
        }

        if (!parsedAny && lastParseError is not null)
        {
            ExceptionDispatchInfo.Capture(lastParseError).Throw();
        }

        return null;
    }

    private async Task<TResult?> SendWebSocketRequestAsync<TResult>(
        string method,
        string requestJson,
        int expectedId,
        CancellationToken cancellationToken) where TResult : class
    {
        if (_webSocket is null || _webSocket.State != WebSocketState.Open)
        {
            throw new InvalidOperationException("WebSocket not connected");
        }

        // Send request
        var requestBytes = Encoding.UTF8.GetBytes(requestJson);

        // Security: Limit request size
        if (requestBytes.Length > 1_000_000)
        {
            throw new InvalidOperationException("Request too large for WebSocket");
        }

        await _webSocket.SendAsync(
            requestBytes.AsMemory(),
            WebSocketMessageType.Text,
            true,
            cancellationToken);

        // Receive response
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_timeout);

        var totalBytesRead = 0;

        while (!cts.Token.IsCancellationRequested)
        {
            var message = await ReceiveWebSocketMessageAsync(cts.Token);
            if (message is null)
            {
                continue;
            }

            // Security: Track total bytes to prevent memory exhaustion
            totalBytesRead += message.Length;
            if (totalBytesRead > MaxResponseSizeBytes)
            {
                throw new InvalidOperationException("WebSocket response too large - possible denial of service");
            }

            try
            {
                using var doc = JsonDocument.Parse(message);
                var root = doc.RootElement;

                // v3.0.0: server-initiated request/notification - record and decline.
                if (root.TryGetProperty("method", out _))
                {
                    var declineJson = RecordUnsolicited(root);
                    if (declineJson is not null)
                    {
                        // Best effort, as in the stdio path: a socket the server closed
                        // immediately after its request must not abort enumeration.
                        try
                        {
                            var declineBytes = Encoding.UTF8.GetBytes(declineJson);
                            await _webSocket.SendAsync(declineBytes.AsMemory(), WebSocketMessageType.Text, true, cts.Token);
                        }
                        catch (WebSocketException)
                        {
                            // Swallowed by design; see comment above.
                        }
                        catch (ObjectDisposedException)
                        {
                            // Swallowed by design; see comment above.
                        }
                    }
                    continue;
                }

                // Check if this is a response (has id)
                if (root.TryGetProperty("id", out var idElement))
                {
                    var responseId = idElement.ValueKind switch
                    {
                        JsonValueKind.Number => idElement.GetInt32(),
                        JsonValueKind.String => int.TryParse(idElement.GetString(), out var parsed) ? parsed : -1,
                        _ => -1
                    };

                    if (responseId == expectedId)
                    {
                        if (root.TryGetProperty("error", out var error))
                        {
                            var errorMsg = RecordProtocolError(method, error);
                            throw new InvalidOperationException($"MCP error: {errorMsg}");
                        }

                        if (root.TryGetProperty("result", out var result))
                        {
                            return JsonSerializer.Deserialize<TResult>(result.GetRawText(), JsonOptions);
                        }

                        return null;
                    }
                }
            }
            catch (JsonException)
            {
                // Not valid JSON, skip
            }
        }

        throw new TimeoutException($"Timeout waiting for WebSocket response from MCP server '{_config.Name}'");
    }

    /// <summary>
    /// Reads a single line from a StreamReader with a maximum length limit.
    /// Prevents memory exhaustion from extremely long lines.
    /// </summary>
    private static async Task<string?> ReadBoundedLineAsync(StreamReader reader, int maxLength, CancellationToken cancellationToken)
    {
        var buffer = new char[4096];
        var sb = new StringBuilder();

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var ch = reader.Peek();
            if (ch == -1)
            {
                // End of stream
                return sb.Length > 0 ? sb.ToString() : null;
            }

            var bytesRead = await reader.ReadAsync(buffer.AsMemory(0, 1), cancellationToken);
            if (bytesRead == 0)
            {
                return sb.Length > 0 ? sb.ToString() : null;
            }

            if (buffer[0] == '\n')
            {
                return sb.ToString();
            }

            if (buffer[0] != '\r')
            {
                sb.Append(buffer[0]);
            }

            if (sb.Length > maxLength)
            {
                throw new InvalidOperationException(
                    $"Stdio line exceeds maximum allowed length of {maxLength / (1024 * 1024)}MB - possible denial of service");
            }
        }
    }

    /// <summary>
    /// Receives a complete WebSocket text message, reassembling fragments.
    /// </summary>
    private async Task<string?> ReceiveWebSocketMessageAsync(CancellationToken cancellationToken)
    {
        if (_webSocket is null)
        {
            return null;
        }

        var buffer = new byte[WebSocketReceiveBufferSize];
        var messageBuilder = new StringBuilder();
        var totalBytes = 0;
        var segment = new ArraySegment<byte>(buffer);

        WebSocketReceiveResult receiveResult;
        do
        {
            receiveResult = await _webSocket.ReceiveAsync(segment, cancellationToken);

            if (receiveResult.MessageType == WebSocketMessageType.Close)
            {
                // Server initiated close
                if (_webSocket.State == WebSocketState.Open || _webSocket.State == WebSocketState.CloseReceived)
                {
                    await _webSocket.CloseOutputAsync(
                        WebSocketCloseStatus.NormalClosure,
                        "Scan complete",
                        cancellationToken);
                }
                throw new InvalidOperationException("WebSocket connection closed by server");
            }

            if (receiveResult.MessageType == WebSocketMessageType.Text)
            {
                totalBytes += receiveResult.Count;

                // Security: Prevent oversized messages
                if (totalBytes > MaxResponseSizeBytes)
                {
                    throw new InvalidOperationException("WebSocket message too large");
                }

                messageBuilder.Append(Encoding.UTF8.GetString(buffer, 0, receiveResult.Count));
            }
        } while (!receiveResult.EndOfMessage);

        var message = messageBuilder.ToString();
        return string.IsNullOrEmpty(message) ? null : message;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_process is not null)
        {
            try
            {
                if (!_process.HasExited)
                {
                    // Security: Give process a chance to exit gracefully
                    _process.Kill(entireProcessTree: true);
                }
            }
            catch
            {
                // Ignore cleanup errors
            }

            _process.Dispose();
            _process = null;
        }

        if (_webSocket is not null)
        {
            try
            {
                if (_webSocket.State == WebSocketState.Open)
                {
                    // Security: Use a 5-second timeout to prevent hanging on dispose
                    using var closeCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await _webSocket.CloseAsync(
                        WebSocketCloseStatus.NormalClosure,
                        "Scanner disconnecting",
                        closeCts.Token);
                }
            }
            catch
            {
                // Ignore cleanup errors
            }

            _webSocket.Dispose();
            _webSocket = null;
        }

        _httpClient?.Dispose();
        _httpClient = null;
    }
}
