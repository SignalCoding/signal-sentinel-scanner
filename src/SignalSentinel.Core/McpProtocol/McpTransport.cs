namespace SignalSentinel.Core.McpProtocol;

/// <summary>
/// v2.5.0 (G13a): reference points for the MCP specification's dated
/// protocol-version scheme, used to flag servers that have not adopted the
/// current spec revision. The <c>2026-07-28</c> release retired the
/// <c>initialize</c>/<c>initialized</c> handshake and <c>Mcp-Session-Id</c>
/// session header in favour of a stateless protocol core, and formally
/// deprecated the legacy HTTP+SSE transport (12-month backward-compatibility
/// window from release). Servers negotiating an older <c>protocolVersion</c>,
/// or reached over legacy HTTP+SSE, still work today but are on a
/// deprecation clock - see <c>SS-INFO-004</c>.
/// </summary>
public static class McpProtocolVersions
{
    /// <summary>
    /// The current MCP specification revision as of this scanner release.
    /// Protocol-version strings are ISO-8601 dates, so ordinal string
    /// comparison against this value is chronologically correct.
    /// </summary>
    public const string Current = "2026-07-28";
}

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
    /// HTTP transport with Server-Sent Events. Formally deprecated by the MCP
    /// <c>2026-07-28</c> specification in favour of Streamable HTTP, with a
    /// 12-month backward-compatibility window. See <c>SS-INFO-004</c>.
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
    /// Optional HTTP request headers to apply on every outgoing MCP call
    /// (HTTP / StreamableHttp / WebSocket transports). Typical use: the
    /// <c>Authorization: Bearer &lt;token&gt;</c> header for OAuth 2.1 protected
    /// MCP servers. Ignored for Stdio transport.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

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
