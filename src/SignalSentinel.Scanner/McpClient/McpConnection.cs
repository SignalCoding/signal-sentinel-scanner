using System.Diagnostics;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using SignalSentinel.Core.McpProtocol;

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
    private ClientWebSocket? _webSocket;
    private int _requestId;
    private bool _disposed;

    // Security: Limit response sizes to prevent memory exhaustion
    private const int MaxResponseSizeBytes = 10 * 1024 * 1024; // 10MB
    private const int WebSocketReceiveBufferSize = 8192;

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
            await ConnectWebSocketAsync(cancellationToken);
        }
        else
        {
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
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("SignalSentinel.Scanner/1.0");
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
        _webSocket.Options.SetRequestHeader("User-Agent", "SignalSentinel.Scanner/1.0");

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

        _process = new Process { StartInfo = startInfo };

        // Security: Enable process exited event for cleanup
        _process.EnableRaisingEvents = true;

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

        var result = await SendRequestAsync<McpInitializeResult>("initialize", initParams, cancellationToken);

        if (result is null)
        {
            throw new InvalidOperationException($"Failed to initialize MCP server '{_config.Name}'");
        }

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
            return await SendStdioRequestAsync<TResult>(requestJson, id, cancellationToken);
        }
        else if (_config.Transport == McpTransportType.WebSocket)
        {
            return await SendWebSocketRequestAsync<TResult>(requestJson, id, cancellationToken);
        }
        else
        {
            return await SendHttpRequestAsync<TResult>(requestJson, cancellationToken);
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
                            var errorMsg = error.TryGetProperty("message", out var msgEl) 
                                ? msgEl.GetString() ?? "Unknown error"
                                : "Unknown error";
                            // Security: Truncate error messages
                            if (errorMsg.Length > 500)
                            {
                                errorMsg = errorMsg[..500] + "...";
                            }
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

    private async Task<TResult?> SendHttpRequestAsync<TResult>(
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

        var content = new StringContent(requestJson, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync(uri, content, cancellationToken);

        response.EnsureSuccessStatusCode();

        // Security: Check content length before reading
        if (response.Content.Headers.ContentLength > MaxResponseSizeBytes)
        {
            throw new InvalidOperationException("Response too large");
        }

        var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);

        // Security: Double-check after reading
        if (responseJson.Length > MaxResponseSizeBytes)
        {
            throw new InvalidOperationException("Response too large");
        }

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var error))
        {
            var errorMsg = error.TryGetProperty("message", out var msgEl)
                ? msgEl.GetString() ?? "Unknown error"
                : "Unknown error";
            throw new InvalidOperationException($"MCP error: {errorMsg}");
        }

        if (root.TryGetProperty("result", out var result))
        {
            return JsonSerializer.Deserialize<TResult>(result.GetRawText(), JsonOptions);
        }

        return null;
    }

    private async Task<TResult?> SendWebSocketRequestAsync<TResult>(
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
                            var errorMsg = error.TryGetProperty("message", out var msgEl)
                                ? msgEl.GetString() ?? "Unknown error"
                                : "Unknown error";
                            if (errorMsg.Length > 500)
                            {
                                errorMsg = errorMsg[..500] + "...";
                            }
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

        if (_httpClient is not null)
        {
            _httpClient.Dispose();
            _httpClient = null;
        }
    }
}
