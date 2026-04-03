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
}

/// <summary>
/// MCP capability info (can contain listChanged subscription support).
/// </summary>
public sealed record McpCapabilityInfo
{
    [JsonPropertyName("listChanged")]
    public bool ListChanged { get; init; }
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
}
