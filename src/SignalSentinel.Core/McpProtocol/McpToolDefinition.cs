using System.Text.Json;
using System.Text.Json.Serialization;

namespace SignalSentinel.Core.McpProtocol;

/// <summary>
/// MCP tool definition as returned by tools/list.
/// </summary>
public sealed record McpToolDefinition
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("inputSchema")]
    public JsonElement? InputSchema { get; init; }
}

/// <summary>
/// MCP resource definition as returned by resources/list.
/// </summary>
public sealed record McpResourceDefinition
{
    [JsonPropertyName("uri")]
    public required string Uri { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("mimeType")]
    public string? MimeType { get; init; }
}

/// <summary>
/// MCP prompt definition as returned by prompts/list.
/// </summary>
public sealed record McpPromptDefinition
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("arguments")]
    public IReadOnlyList<McpPromptArgument>? Arguments { get; init; }
}

/// <summary>
/// MCP prompt argument definition.
/// </summary>
public sealed record McpPromptArgument
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("required")]
    public bool Required { get; init; }
}

/// <summary>
/// MCP server capabilities as returned by initialize response.
/// </summary>
public sealed record McpServerCapabilities
{
    [JsonPropertyName("tools")]
    public McpCapabilityInfo? Tools { get; init; }

    [JsonPropertyName("resources")]
    public McpCapabilityInfo? Resources { get; init; }

    [JsonPropertyName("prompts")]
    public McpCapabilityInfo? Prompts { get; init; }

    [JsonPropertyName("logging")]
    public McpCapabilityInfo? Logging { get; init; }

    /// <summary>
    /// v3.0.0: <c>completions</c> capability (argument autocompletion for prompts/resources).
    /// </summary>
    [JsonPropertyName("completions")]
    public McpCapabilityInfo? Completions { get; init; }

    /// <summary>
    /// v3.0.0: server-defined <c>experimental</c> capabilities. Kept as raw JSON because
    /// the shape is vendor-specific; SS-INFO-005 reports the top-level keys.
    /// </summary>
    [JsonPropertyName("experimental")]
    public JsonElement? Experimental { get; init; }
}

/// <summary>
/// MCP capability info (can contain listChanged subscription support).
/// </summary>
public sealed record McpCapabilityInfo
{
    [JsonPropertyName("listChanged")]
    public bool ListChanged { get; init; }

    /// <summary>
    /// v3.0.0: <c>subscribe</c> flag on the resources capability (server can push
    /// <c>notifications/resources/updated</c> for subscribed URIs).
    /// </summary>
    [JsonPropertyName("subscribe")]
    public bool Subscribe { get; init; }
}

/// <summary>
/// MCP server info returned in initialize response.
/// </summary>
public sealed record McpServerInfo
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("version")]
    public required string Version { get; init; }
}

/// <summary>
/// Result of tools/list method.
/// </summary>
public sealed record McpToolsListResult
{
    [JsonPropertyName("tools")]
    public required IReadOnlyList<McpToolDefinition> Tools { get; init; }
}

/// <summary>
/// Result of resources/list method.
/// </summary>
public sealed record McpResourcesListResult
{
    [JsonPropertyName("resources")]
    public required IReadOnlyList<McpResourceDefinition> Resources { get; init; }
}

/// <summary>
/// Result of prompts/list method.
/// </summary>
public sealed record McpPromptsListResult
{
    [JsonPropertyName("prompts")]
    public required IReadOnlyList<McpPromptDefinition> Prompts { get; init; }
}

/// <summary>
/// Result of initialize method.
/// </summary>
public sealed record McpInitializeResult
{
    [JsonPropertyName("protocolVersion")]
    public required string ProtocolVersion { get; init; }

    [JsonPropertyName("capabilities")]
    public required McpServerCapabilities Capabilities { get; init; }

    [JsonPropertyName("serverInfo")]
    public required McpServerInfo ServerInfo { get; init; }

    /// <summary>
    /// v3.0.0: optional free-text <c>instructions</c> the server asks the client to place
    /// in the model's system prompt. This is a direct prompt-injection channel and is
    /// evaluated by SS-032.
    /// </summary>
    [JsonPropertyName("instructions")]
    public string? Instructions { get; init; }
}

/// <summary>
/// v3.0.0: a JSON-RPC request or notification the server sent to the client without
/// the client having declared the corresponding capability. Captured by
/// <c>McpConnection</c> while it waits for its own responses. Powers SS-033.
/// </summary>
public sealed record McpUnsolicitedRequest
{
    /// <summary>JSON-RPC method name (e.g. <c>sampling/createMessage</c>).</summary>
    public required string Method { get; init; }

    /// <summary>True when the message carried an <c>id</c> (a request expecting a reply).</summary>
    public bool IsRequest { get; init; }

    /// <summary>First 200 characters of the serialised <c>params</c>, control characters removed.</summary>
    public string? ParamsSnippet { get; init; }
}

/// <summary>
/// v3.0.0: a JSON-RPC error object the server returned for one of the scanner's
/// requests. Error <c>message</c> bodies are an under-scrutinised injection channel
/// (the client typically relays them verbatim to the model). Powers SS-040.
/// </summary>
public sealed record McpProtocolError
{
    /// <summary>The method the scanner had sent (e.g. <c>tools/list</c>).</summary>
    public required string Method { get; init; }

    /// <summary>JSON-RPC error code, or 0 when absent.</summary>
    public int Code { get; init; }

    /// <summary>Error message, truncated to 500 characters and control-character stripped.</summary>
    public required string Message { get; init; }
}
