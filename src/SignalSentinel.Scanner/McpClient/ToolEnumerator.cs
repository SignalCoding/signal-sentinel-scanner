using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.McpClient;

/// <summary>
/// Enumerates tools, resources, and prompts from MCP servers.
/// Security hardened with timeout enforcement and resource limits.
/// </summary>
public sealed class ToolEnumerator(TimeSpan timeout, bool verbose = false, Action<string>? logger = null)
{
    private readonly TimeSpan _timeout = timeout;
    private readonly bool _verbose = verbose;
    private readonly Action<string>? _logger = logger;

    // Security: Limit maximum items to prevent memory exhaustion
    private const int MaxToolsPerServer = 10_000;
    private const int MaxResourcesPerServer = 10_000;
    private const int MaxPromptsPerServer = 1_000;
    private const int MaxServers = 100;

    /// <summary>
    /// Enumerates all MCP servers from configuration files.
    /// </summary>
    public async Task<IReadOnlyList<ServerEnumeration>> EnumerateServersAsync(
        IReadOnlyList<McpConfigFile> configFiles,
        CancellationToken cancellationToken = default)
    {
        var results = new List<ServerEnumeration>();
        var serverCount = 0;

        foreach (var configFile in configFiles)
        {
            foreach (var serverConfig in configFile.Servers)
            {
                // Security: Limit total servers to prevent resource exhaustion
                if (++serverCount > MaxServers)
                {
                    Log($"Warning: Maximum server limit ({MaxServers}) reached. Skipping remaining servers.");
                    break;
                }

                // Security: Check cancellation before each server
                cancellationToken.ThrowIfCancellationRequested();

                // Security: Sanitize server name for logging
                var safeName = SanitizeForLogging(serverConfig.Name);
                Log($"Enumerating server: {safeName} ({serverConfig.Transport})");

                var enumeration = await EnumerateServerAsync(serverConfig, cancellationToken);
                enumeration = enumeration with
                {
                    SourceApplication = configFile.SourceApplication,
                    SourceConfigPath = configFile.FilePath
                };

                results.Add(enumeration);
            }

            if (serverCount > MaxServers)
            {
                break;
            }
        }

        return results;
    }

    /// <summary>
    /// Enumerates a single MCP server with timeout enforcement.
    /// </summary>
    public async Task<ServerEnumeration> EnumerateServerAsync(
        McpServerConfig config,
        CancellationToken cancellationToken = default)
    {
        var result = new ServerEnumeration
        {
            ServerConfig = config,
            ServerName = config.Name,
            Transport = config.Transport.ToString()
        };

        // Security: Create a timeout cancellation token
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_timeout.Add(TimeSpan.FromSeconds(30))); // Extra buffer for cleanup

        try
        {
            await using var connection = new McpConnection(config, _timeout);

            var safeName = SanitizeForLogging(config.Name);
            Log($"  Connecting to {safeName}...");

            var initResult = await connection.ConnectAsync(timeoutCts.Token);

            result = result with
            {
                ServerVersion = SanitizeForLogging(initResult.ServerInfo.Version),
                ProtocolVersion = initResult.ProtocolVersion,
                Capabilities = initResult.Capabilities,
                ConnectionSuccessful = true
            };

            Log($"  Connected: {SanitizeForLogging(initResult.ServerInfo.Name)} v{SanitizeForLogging(initResult.ServerInfo.Version)}");

            // Enumerate tools with limits
            if (initResult.Capabilities.Tools is not null)
            {
                Log($"  Listing tools...");
                var toolsResult = await connection.ListToolsAsync(timeoutCts.Token);

                // Security: Enforce tool count limit
                var tools = toolsResult.Tools.Take(MaxToolsPerServer).ToList();
                if (toolsResult.Tools.Count > MaxToolsPerServer)
                {
                    Log($"  Warning: Tool count ({toolsResult.Tools.Count}) exceeds limit. Truncated to {MaxToolsPerServer}.");
                }

                // Security: Validate and sanitize tool data
                var sanitizedTools = tools.Select(SanitizeTool).ToList();
                result = result with { Tools = sanitizedTools };
                Log($"  Found {sanitizedTools.Count} tools");
            }

            // Enumerate resources with limits
            if (initResult.Capabilities.Resources is not null)
            {
                Log($"  Listing resources...");
                var resourcesResult = await connection.ListResourcesAsync(timeoutCts.Token);

                // Security: Enforce resource count limit
                var resources = resourcesResult.Resources.Take(MaxResourcesPerServer).ToList();
                if (resourcesResult.Resources.Count > MaxResourcesPerServer)
                {
                    Log($"  Warning: Resource count ({resourcesResult.Resources.Count}) exceeds limit. Truncated to {MaxResourcesPerServer}.");
                }

                result = result with { Resources = resources };
                Log($"  Found {resources.Count} resources");
            }

            // Enumerate prompts with limits
            if (initResult.Capabilities.Prompts is not null)
            {
                Log($"  Listing prompts...");
                var promptsResult = await connection.ListPromptsAsync(timeoutCts.Token);

                // Security: Enforce prompt count limit
                var prompts = promptsResult.Prompts.Take(MaxPromptsPerServer).ToList();
                if (promptsResult.Prompts.Count > MaxPromptsPerServer)
                {
                    Log($"  Warning: Prompt count ({promptsResult.Prompts.Count}) exceeds limit. Truncated to {MaxPromptsPerServer}.");
                }

                result = result with { Prompts = prompts };
                Log($"  Found {prompts.Count} prompts");
            }
        }
        catch (NonMcpEndpointException ex)
        {
            // v2.3.0: endpoint reachable but not an MCP server. Capture evidence so
            // SS-INFO-001 can surface an informational finding; do not treat this as
            // a scan-time error.
            Log($"  Non-MCP endpoint: {ex.ReasonText}");
            result = result with
            {
                ConnectionSuccessful = false,
                ConnectionError = $"Non-MCP endpoint: {ex.ReasonText}",
                NonMcpEvidence = new NonMcpEndpointEvidence
                {
                    ContentType = ex.ContentType,
                    BodySnippet = ex.BodySnippet,
                    Reason = ex.ReasonText
                }
            };
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            // Security: Differentiate between user cancellation and timeout
            Log($"  Timeout: Server did not respond within allowed time");
            result = result with
            {
                ConnectionSuccessful = false,
                ConnectionError = "Connection timeout - server did not respond in time"
            };
        }
        catch (Exception ex)
        {
            // Security: Sanitize error messages before logging
            var safeError = SanitizeErrorMessage(ex.Message);
            Log($"  Error: {safeError}");
            result = result with
            {
                ConnectionSuccessful = false,
                ConnectionError = safeError
            };
        }

        return result;
    }

    /// <summary>
    /// Sanitizes a tool definition to prevent malicious data from propagating.
    /// </summary>
    private static McpToolDefinition SanitizeTool(McpToolDefinition tool)
    {
        const int maxNameLength = 256;
        const int maxDescriptionLength = 100_000;

        var name = tool.Name;
        var description = tool.Description;

        // Security: Truncate excessively long names
        if (name.Length > maxNameLength)
        {
            name = name[..maxNameLength];
        }

        // Security: Truncate excessively long descriptions
        if (description is not null && description.Length > maxDescriptionLength)
        {
            description = description[..maxDescriptionLength] + "... (truncated)";
        }

        // Security: Remove null bytes and control characters from name
        name = RemoveControlCharacters(name);

        return tool with
        {
            Name = name,
            Description = description
        };
    }

    /// <summary>
    /// Removes control characters that could be used for log injection.
    /// </summary>
    private static string RemoveControlCharacters(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        var result = new char[input.Length];
        var index = 0;

        foreach (var c in input)
        {
            // Allow printable characters and common whitespace
            if (!char.IsControl(c) || c == ' ' || c == '\t')
            {
                result[index++] = c;
            }
        }

        return new string(result, 0, index);
    }

    /// <summary>
    /// Sanitizes text for safe logging (prevents log injection).
    /// </summary>
    private static string SanitizeForLogging(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return "(empty)";
        }

        // Security: Limit length
        if (input.Length > 200)
        {
            input = input[..200] + "...";
        }

        // Security: Remove newlines and control characters to prevent log injection
        return RemoveControlCharacters(input)
            .Replace("\r", "")
            .Replace("\n", " ");
    }

    /// <summary>
    /// Sanitizes error messages to prevent sensitive data leakage.
    /// </summary>
    private static string SanitizeErrorMessage(string message)
    {
        if (string.IsNullOrEmpty(message))
        {
            return "Unknown error";
        }

        // Security: Limit length
        if (message.Length > 500)
        {
            message = message[..500] + "...";
        }

        // Security: Remove potential path information
        message = SanitizeForLogging(message);

        // Security: Remove potential secrets (basic patterns)
        var patterns = new[]
        {
            @"(?i)(api[_-]?key|password|secret|token|bearer)\s*[=:]\s*\S+",
            @"(?i)authorization:\s*\S+",
        };

        foreach (var pattern in patterns)
        {
            message = System.Text.RegularExpressions.Regex.Replace(
                message,
                pattern,
                "[REDACTED]",
                System.Text.RegularExpressions.RegexOptions.None,
                TimeSpan.FromMilliseconds(100)); // Timeout for regex
        }

        return message;
    }

    private void Log(string message)
    {
        if (_verbose)
        {
            _logger?.Invoke(message);
        }
    }
}

/// <summary>
/// Result of enumerating a single MCP server.
/// </summary>
public sealed record ServerEnumeration
{
    public required McpServerConfig ServerConfig { get; init; }
    public required string ServerName { get; init; }
    public required string Transport { get; init; }
    public string? ServerVersion { get; init; }
    public string? ProtocolVersion { get; init; }
    public McpServerCapabilities? Capabilities { get; init; }
    public bool ConnectionSuccessful { get; init; }
    public string? ConnectionError { get; init; }
    public string? SourceApplication { get; init; }
    public string? SourceConfigPath { get; init; }
    public IReadOnlyList<McpToolDefinition> Tools { get; init; } = [];
    public IReadOnlyList<McpResourceDefinition> Resources { get; init; } = [];
    public IReadOnlyList<McpPromptDefinition> Prompts { get; init; } = [];

    /// <summary>
    /// v2.3.0: populated when the scanner detects the remote endpoint is not an MCP
    /// server at all (e.g. a React SPA returning <c>text/html</c> for every path).
    /// </summary>
    public NonMcpEndpointEvidence? NonMcpEvidence { get; init; }
}

/// <summary>
/// Evidence captured when an endpoint responds with something that is clearly not an
/// MCP transport (HTML, non-JSON-RPC body, etc.). Powers SS-INFO-001.
/// </summary>
public sealed record NonMcpEndpointEvidence
{
    /// <summary>
    /// Content-Type header observed on the first response (e.g. "text/html; charset=utf-8").
    /// </summary>
    public string? ContentType { get; init; }

    /// <summary>
    /// First ~200 characters of the response body, used only for diagnostic display.
    /// Already sanitised (control characters removed, newlines collapsed to spaces).
    /// </summary>
    public string? BodySnippet { get; init; }

    /// <summary>
    /// Short explanation of why this was classified as non-MCP.
    /// </summary>
    public string? Reason { get; init; }
}
