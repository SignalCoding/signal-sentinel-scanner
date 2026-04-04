namespace SignalSentinel.Core.McpProtocol;

/// <summary>
/// Supported MCP transport types.
/// </summary>
public enum McpTransportType
{
    /// <summary>
    /// Standard I/O transport (stdin/stdout).
    /// </summary>
    Stdio,

    /// <summary>
    /// HTTP transport with Server-Sent Events.
    /// </summary>
    Http,

    /// <summary>
    /// Streamable HTTP transport (latest MCP spec).
    /// </summary>
    StreamableHttp,

    /// <summary>
    /// WebSocket transport (ws:// or wss://).
    /// </summary>
    WebSocket
}

/// <summary>
/// MCP server configuration from config files.
/// </summary>
public sealed record McpServerConfig
{
    /// <summary>
    /// Server name/identifier.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Transport type (stdio, http, streamable-http).
    /// </summary>
    public McpTransportType Transport { get; init; } = McpTransportType.Stdio;

    /// <summary>
    /// Command to execute (for stdio transport).
    /// </summary>
    public string? Command { get; init; }

    /// <summary>
    /// Arguments for the command (for stdio transport).
    /// </summary>
    public IReadOnlyList<string>? Args { get; init; }

    /// <summary>
    /// Environment variables for the command.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Env { get; init; }

    /// <summary>
    /// URL endpoint (for HTTP transport).
    /// </summary>
    public string? Url { get; init; }

    /// <summary>
    /// Source config file path (for reporting).
    /// </summary>
    public string? SourceConfigPath { get; init; }
}

/// <summary>
/// Aggregated MCP configuration from a config file.
/// </summary>
public sealed record McpConfigFile
{
    /// <summary>
    /// Path to the configuration file.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Source application (Claude Desktop, Cursor, VS Code, etc.).
    /// </summary>
    public required string SourceApplication { get; init; }

    /// <summary>
    /// Configured MCP servers.
    /// </summary>
    public required IReadOnlyList<McpServerConfig> Servers { get; init; }
}
