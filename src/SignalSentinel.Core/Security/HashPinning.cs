using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SignalSentinel.Core.McpProtocol;

namespace SignalSentinel.Core.Security;

/// <summary>
/// Provides hash-based integrity verification for MCP tool definitions.
/// Used for OWASP ASI04 (Supply Chain Vulnerabilities) - rug pull detection.
/// </summary>
public static class HashPinning
{
    /// <summary>
    /// Computes a SHA-256 hash of a tool definition for integrity verification.
    /// </summary>
    /// <param name="tool">The tool definition to hash.</param>
    /// <returns>Hex-encoded SHA-256 hash.</returns>
    public static string ComputeToolHash(McpToolDefinition tool)
    {
        ArgumentNullException.ThrowIfNull(tool);

        var normalizedContent = new StringBuilder();
        normalizedContent.Append("name:");
        normalizedContent.Append(tool.Name);
        normalizedContent.Append("|description:");
        normalizedContent.Append(tool.Description ?? string.Empty);
        normalizedContent.Append("|schema:");

        if (tool.InputSchema.HasValue)
        {
            normalizedContent.Append(NormalizeJson(tool.InputSchema.Value));
        }

        var bytes = Encoding.UTF8.GetBytes(normalizedContent.ToString());
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Computes a SHA-256 hash of a server's complete tool manifest.
    /// </summary>
    /// <param name="serverName">Server name.</param>
    /// <param name="tools">Tools exposed by the server.</param>
    /// <returns>Hex-encoded SHA-256 hash.</returns>
    public static string ComputeServerManifestHash(string serverName, IEnumerable<McpToolDefinition> tools)
    {
        ArgumentNullException.ThrowIfNull(serverName);
        ArgumentNullException.ThrowIfNull(tools);

        var sortedHashes = tools
            .OrderBy(t => t.Name, StringComparer.Ordinal)
            .Select(ComputeToolHash);

        var combinedContent = new StringBuilder();
        combinedContent.Append("server:");
        combinedContent.Append(serverName);
        combinedContent.Append("|tools:");

        foreach (var hash in sortedHashes)
        {
            combinedContent.Append(hash);
            combinedContent.Append(',');
        }

        var bytes = Encoding.UTF8.GetBytes(combinedContent.ToString());
        var manifestHash = SHA256.HashData(bytes);
        return Convert.ToHexString(manifestHash).ToLowerInvariant();
    }

    /// <summary>
    /// Verifies if a tool hash matches the expected pinned hash.
    /// </summary>
    /// <param name="tool">Tool to verify.</param>
    /// <param name="expectedHash">Expected hash value.</param>
    /// <returns>True if hashes match.</returns>
    public static bool VerifyToolHash(McpToolDefinition tool, string expectedHash)
    {
        var actualHash = ComputeToolHash(tool);
        return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Compares two manifests and returns changes.
    /// </summary>
    public static ManifestComparison CompareManifests(
        string serverName,
        IReadOnlyList<McpToolDefinition> previousTools,
        IReadOnlyList<McpToolDefinition> currentTools)
    {
        var previousDict = previousTools.ToDictionary(t => t.Name, ComputeToolHash);
        var currentDict = currentTools.ToDictionary(t => t.Name, ComputeToolHash);

        var added = currentDict.Keys.Except(previousDict.Keys).ToList();
        var removed = previousDict.Keys.Except(currentDict.Keys).ToList();
        var modified = previousDict.Keys
            .Intersect(currentDict.Keys)
            .Where(name => previousDict[name] != currentDict[name])
            .ToList();

        return new ManifestComparison
        {
            ServerName = serverName,
            PreviousHash = ComputeServerManifestHash(serverName, previousTools),
            CurrentHash = ComputeServerManifestHash(serverName, currentTools),
            AddedTools = added,
            RemovedTools = removed,
            ModifiedTools = modified,
            HasChanges = added.Count > 0 || removed.Count > 0 || modified.Count > 0
        };
    }

    private static string NormalizeJson(JsonElement element)
    {
        return JsonSerializer.Serialize(element, new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }
}

/// <summary>
/// Result of comparing two server manifests.
/// </summary>
public sealed record ManifestComparison
{
    public required string ServerName { get; init; }
    public required string PreviousHash { get; init; }
    public required string CurrentHash { get; init; }
    public required IReadOnlyList<string> AddedTools { get; init; }
    public required IReadOnlyList<string> RemovedTools { get; init; }
    public required IReadOnlyList<string> ModifiedTools { get; init; }
    public required bool HasChanges { get; init; }
}
