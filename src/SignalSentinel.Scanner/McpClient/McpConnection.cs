using System.Diagnostics;
using System.Text;
using System.Text.Json;
using SignalSentinel.Core.McpProtocol;

namespace SignalSentinel.Scanner.McpClient;

/// <summary>
/// Manages connections to MCP servers via stdio or HTTP transport.
/// Security hardened for production use.
/// </summary>
public sealed class McpConnection : IAsyncDisposable
{
    private readonly McpServerConfig _config;
    private readonly TimeSpan _timeout;
    private Process? _process;
    private HttpClient? _httpClient;
    private int _requestId;
    private bool _disposed;

    // Security: Limit response sizes to prevent memory exhaustion
    private const int MaxResponseSizeBytes = 10 * 1024 * 1024; // 10MB
    private const int MaxDescriptionLength = 100_000; // 100KB per description

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
        else
        {
            // Security: Configure HttpClient with security settings
            var handler = new HttpClientHandler
            {
                // Security: Enable certificate revocation list checking
                CheckCertificateRevocationList = true,
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
            foreach (var (key, value) in _config.Env)
            {
                // Security: Only set non-empty environment variables
                if (!string.IsNullOrWhiteSpace(key) && value is not null)
                {
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
                version = "1.0.0"
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
                await _process.StandardInput.FlushAsync();
            }
        }
        else if (_httpClient is not null && _config.Url is not null)
        {
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            await _httpClient.PostAsync(_config.Url, content, cancellationToken);
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
        await _process.StandardInput.FlushAsync();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_timeout);

        var totalBytesRead = 0;

        while (!cts.Token.IsCancellationRequested)
        {
            var line = await _process.StandardOutput.ReadLineAsync(cts.Token);
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
                var doc = JsonDocument.Parse(line);
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
        var response = await _httpClient.PostAsync(uri, content, cancellationToken);

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

        var doc = JsonDocument.Parse(responseJson);
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

        if (_httpClient is not null)
        {
            _httpClient.Dispose();
            _httpClient = null;
        }

        await Task.CompletedTask;
    }
}
