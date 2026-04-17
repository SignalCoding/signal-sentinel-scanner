// -----------------------------------------------------------------------
// <copyright file="SchemaHasher.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SignalSentinel.Core.McpProtocol;

namespace SignalSentinel.Scanner.Baseline;

/// <summary>
/// Produces stable SHA-256 hashes of MCP tool schemas for rug-pull detection (SS-022).
/// </summary>
/// <remarks>
/// Hashes are computed over canonicalised inputs so that whitespace-only changes
/// do not trigger false mutation detections.
/// </remarks>
public static class SchemaHasher
{
    /// <summary>
    /// Computes the hash of the tool description text.
    /// </summary>
    /// <param name="description">The tool description.</param>
    /// <returns>Lowercase hex SHA-256 hash prefixed with "sha256:".</returns>
    public static string HashDescription(string? description)
    {
        var normalised = Normalise(description ?? string.Empty);
        return ComputeHash(normalised);
    }

    /// <summary>
    /// Computes the hash of the tool parameters schema (JSON).
    /// </summary>
    /// <param name="parameters">Tool input schema as parsed JSON tree, or null.</param>
    /// <returns>Lowercase hex SHA-256 hash prefixed with "sha256:".</returns>
    public static string HashParameters(JsonElement? parameters)
    {
        if (parameters is null)
        {
            return ComputeHash("null");
        }

        var canonical = CanonicaliseJson(parameters.Value);
        return ComputeHash(canonical);
    }

    /// <summary>
    /// Computes a combined hash of description + parameters for quick equality tests.
    /// </summary>
    /// <param name="tool">The tool definition.</param>
    /// <returns>Lowercase hex SHA-256 hash prefixed with "sha256:".</returns>
    public static string HashTool(McpToolDefinition tool)
    {
        ArgumentNullException.ThrowIfNull(tool);
        var combined = $"{HashDescription(tool.Description)}|{HashParameters(tool.InputSchema)}";
        return ComputeHash(combined);
    }

    private static string Normalise(string input)
    {
        // Canonicalise line endings and trim trailing whitespace on each line.
        var normalised = input.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        var lines = normalised.Split('\n').Select(l => l.TrimEnd());
        return string.Join('\n', lines).Trim();
    }

    private static string CanonicaliseJson(JsonElement element)
    {
        // Serialise with sorted property order for stability.
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteCanonical(writer, element);
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var prop in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(prop.Name);
                    WriteCanonical(writer, prop.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteCanonical(writer, item);
                }
                writer.WriteEndArray();
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }

    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        var hex = new StringBuilder(hash.Length * 2);
        foreach (var b in hash)
        {
#pragma warning disable CA1305 // FormatProvider not required for "x2" (invariant hex formatting)
            hex.Append(b.ToString("x2"));
#pragma warning restore CA1305
        }
        return $"sha256:{hex}";
    }
}
