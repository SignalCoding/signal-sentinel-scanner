// -----------------------------------------------------------------------
// <copyright file="BaselineManager.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using System.Text.Json.Serialization;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;

namespace SignalSentinel.Scanner.Baseline;

/// <summary>
/// Loads, saves, and compares baseline files that snapshot MCP tool schemas.
/// Supports rug-pull detection (SS-022) and future suppression workflows.
/// </summary>
public sealed class BaselineManager
{
    private const int MaxBaselineFileSizeBytes = 50 * 1024 * 1024;
    private const string CurrentSchemaVersion = "1.0";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    /// <summary>
    /// Loads a baseline file from disk. Returns null if the file does not exist.
    /// Throws if the file exists but is malformed or exceeds size limits.
    /// </summary>
    /// <param name="path">Absolute or relative path to the baseline JSON file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Parsed baseline or null if the file does not exist.</returns>
    public static async Task<BaselineFile?> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            return null;
        }

        var info = new FileInfo(path);
        if (info.Length > MaxBaselineFileSizeBytes)
        {
            throw new InvalidOperationException(
                $"Baseline file exceeds maximum size of {MaxBaselineFileSizeBytes / (1024 * 1024)}MB.");
        }

        await using var stream = File.OpenRead(path);
        var baseline = await JsonSerializer.DeserializeAsync<BaselineFile>(stream, JsonOptions, cancellationToken)
            .ConfigureAwait(false) ?? throw new InvalidOperationException("Baseline file could not be parsed.");
        return baseline;
    }

    /// <summary>
    /// Writes a baseline file to disk, building it from the given server enumerations.
    /// </summary>
    /// <param name="path">Destination path.</param>
    /// <param name="servers">Server enumerations to capture.</param>
    /// <param name="scannerVersion">Scanner version producing the baseline.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task SaveAsync(
        string path,
        IReadOnlyList<ServerEnumeration> servers,
        string scannerVersion,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentException.ThrowIfNullOrWhiteSpace(scannerVersion);

        var baseline = Build(servers, scannerVersion);
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, baseline, JsonOptions, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Builds a baseline from the current server enumerations.
    /// </summary>
    /// <param name="servers">Server enumerations to capture.</param>
    /// <param name="scannerVersion">Scanner version producing the baseline.</param>
    /// <returns>In-memory baseline representation.</returns>
    public static BaselineFile Build(IReadOnlyList<ServerEnumeration> servers, string scannerVersion)
    {
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentException.ThrowIfNullOrWhiteSpace(scannerVersion);

        var serverSnapshots = new Dictionary<string, BaselineServer>(StringComparer.Ordinal);
        foreach (var server in servers)
        {
            if (!server.ConnectionSuccessful)
            {
                continue;
            }

            var tools = new Dictionary<string, BaselineTool>(StringComparer.Ordinal);
            foreach (var tool in server.Tools)
            {
                // Use first occurrence of duplicate tool names (matches HashPinning behaviour)
                if (tools.ContainsKey(tool.Name))
                {
                    continue;
                }

                tools[tool.Name] = new BaselineTool
                {
                    DescriptionHash = SchemaHasher.HashDescription(tool.Description),
                    ParametersHash = SchemaHasher.HashParameters(tool.InputSchema)
                };
            }

            serverSnapshots[server.ServerName] = new BaselineServer
            {
                Tools = tools,
                ToolCount = tools.Count
            };
        }

        return new BaselineFile
        {
            Version = CurrentSchemaVersion,
            GeneratedAt = DateTimeOffset.UtcNow,
            ScannerVersion = scannerVersion,
            Servers = serverSnapshots
        };
    }

    /// <summary>
    /// Compares current server enumerations against a baseline.
    /// </summary>
    /// <param name="baseline">Previously-saved baseline. Null returns an empty comparison.</param>
    /// <param name="servers">Current server enumerations.</param>
    /// <returns>Comparison result with mutations, additions, and removals populated.</returns>
    public static BaselineComparison Compare(BaselineFile? baseline, IReadOnlyList<ServerEnumeration> servers)
    {
        ArgumentNullException.ThrowIfNull(servers);

        if (baseline is null)
        {
            return new BaselineComparison { BaselineLoaded = false };
        }

        var mutations = new List<SchemaMutation>();
        var additions = new List<ToolIdentity>();
        var removals = new List<ToolIdentity>();

        var currentSnapshot = Build(servers, baseline.ScannerVersion);

        // Detect mutations and additions (walk current vs baseline)
        foreach (var (serverName, currentServer) in currentSnapshot.Servers)
        {
            if (!baseline.Servers.TryGetValue(serverName, out var baselineServer))
            {
                // Entire server is new - all tools are additions
                foreach (var toolName in currentServer.Tools.Keys)
                {
                    additions.Add(new ToolIdentity { ServerName = serverName, ToolName = toolName });
                }
                continue;
            }

            foreach (var (toolName, currentTool) in currentServer.Tools)
            {
                if (!baselineServer.Tools.TryGetValue(toolName, out var baselineTool))
                {
                    additions.Add(new ToolIdentity { ServerName = serverName, ToolName = toolName });
                    continue;
                }

                var descChanged = !string.Equals(
                    baselineTool.DescriptionHash,
                    currentTool.DescriptionHash,
                    StringComparison.Ordinal);
                var paramsChanged = !string.Equals(
                    baselineTool.ParametersHash,
                    currentTool.ParametersHash,
                    StringComparison.Ordinal);

                if (descChanged || paramsChanged)
                {
                    var type = (descChanged, paramsChanged) switch
                    {
                        (true, true) => MutationType.BothChanged,
                        (true, false) => MutationType.DescriptionChanged,
                        _ => MutationType.ParametersChanged
                    };

                    mutations.Add(new SchemaMutation
                    {
                        Tool = new ToolIdentity { ServerName = serverName, ToolName = toolName },
                        Type = type,
                        BaselineHash = $"{baselineTool.DescriptionHash};{baselineTool.ParametersHash}",
                        CurrentHash = $"{currentTool.DescriptionHash};{currentTool.ParametersHash}",
                        Summary = BuildMutationSummary(type)
                    });
                }
            }
        }

        // Detect removals (walk baseline vs current)
        foreach (var (serverName, baselineServer) in baseline.Servers)
        {
            if (!currentSnapshot.Servers.TryGetValue(serverName, out var currentServer))
            {
                foreach (var toolName in baselineServer.Tools.Keys)
                {
                    removals.Add(new ToolIdentity { ServerName = serverName, ToolName = toolName });
                }
                continue;
            }

            foreach (var toolName in baselineServer.Tools.Keys)
            {
                if (!currentServer.Tools.ContainsKey(toolName))
                {
                    removals.Add(new ToolIdentity { ServerName = serverName, ToolName = toolName });
                }
            }
        }

        return new BaselineComparison
        {
            BaselineLoaded = true,
            BaselineScannerVersion = baseline.ScannerVersion,
            BaselineGeneratedAt = baseline.GeneratedAt,
            MutatedTools = mutations,
            AddedTools = additions,
            RemovedTools = removals
        };
    }

    private static string BuildMutationSummary(MutationType type) => type switch
    {
        MutationType.DescriptionChanged => "Tool description has changed since baseline.",
        MutationType.ParametersChanged => "Tool parameter schema has changed since baseline.",
        MutationType.BothChanged => "Tool description and parameter schema have both changed since baseline.",
        _ => "Tool schema has changed since baseline."
    };
}

/// <summary>
/// Persistent baseline file format (v1.0).
/// </summary>
public sealed record BaselineFile
{
    /// <summary>
    /// Schema version for the baseline file format.
    /// </summary>
    public required string Version { get; init; }

    /// <summary>
    /// Timestamp the baseline was generated (UTC).
    /// </summary>
    public required DateTimeOffset GeneratedAt { get; init; }

    /// <summary>
    /// Scanner version that produced the baseline.
    /// </summary>
    public required string ScannerVersion { get; init; }

    /// <summary>
    /// Per-server snapshots keyed by server name.
    /// </summary>
    public required IReadOnlyDictionary<string, BaselineServer> Servers { get; init; }
}

/// <summary>
/// Baseline snapshot of a single server's tools.
/// </summary>
public sealed record BaselineServer
{
    /// <summary>
    /// Tool hashes keyed by tool name.
    /// </summary>
    public required IReadOnlyDictionary<string, BaselineTool> Tools { get; init; }

    /// <summary>
    /// Number of tools captured.
    /// </summary>
    public int ToolCount { get; init; }
}

/// <summary>
/// Baseline snapshot of a single tool.
/// </summary>
public sealed record BaselineTool
{
    /// <summary>
    /// SHA-256 hash of the tool description.
    /// </summary>
    public required string DescriptionHash { get; init; }

    /// <summary>
    /// SHA-256 hash of the canonicalised tool parameter schema.
    /// </summary>
    public required string ParametersHash { get; init; }
}
