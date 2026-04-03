// -----------------------------------------------------------------------
// <copyright file="TyposquatDetector.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Core.Security;

/// <summary>
/// Detects potential typosquatting attempts in MCP server names.
/// Used for OWASP ASI04 (Supply Chain Vulnerabilities) detection.
/// </summary>
/// <remarks>
/// <para>
/// Typosquatting is a supply chain attack where malicious actors register
/// package/server names similar to legitimate ones to trick users into
/// installing malicious software.
/// </para>
/// <para>
/// This detector uses multiple techniques:
/// <list type="bullet">
///   <item><description>Levenshtein distance calculation for similarity</description></item>
///   <item><description>Leet-speak substitution detection (0→o, 1→l, etc.)</description></item>
///   <item><description>Suspicious prefix/suffix detection (real-, -official, etc.)</description></item>
/// </list>
/// </para>
/// </remarks>
public static class TyposquatDetector
{
    /// <summary>
    /// Known legitimate MCP server names/packages from major registries.
    /// </summary>
    private static readonly HashSet<string> KnownLegitimateServers = new(StringComparer.OrdinalIgnoreCase)
    {
        // Anthropic official
        "claude-desktop", "claude-code", "mcp-server-memory", "mcp-server-filesystem",
        "mcp-server-fetch", "mcp-server-github", "mcp-server-gitlab", "mcp-server-slack",
        "mcp-server-postgres", "mcp-server-sqlite", "mcp-server-puppeteer", "mcp-server-brave-search",
        
        // Microsoft official
        "azure-mcp-server", "vscode-mcp-server", "copilot-mcp-server",
        
        // Common third-party
        "cursor-mcp-server", "windsurf-mcp", "raycast-mcp",
        
        // Database servers
        "mcp-server-mysql", "mcp-server-mongodb", "mcp-server-redis",
        
        // Cloud providers
        "aws-mcp-server", "gcp-mcp-server"
    };

    /// <summary>
    /// Leet-speak character substitutions used in typosquatting.
    /// </summary>
    private static readonly Dictionary<char, char> LeetSubstitutions = new()
    {
        { '0', 'o' },
        { '1', 'l' },
        { '3', 'e' },
        { '4', 'a' },
        { '5', 's' }
    };

    /// <summary>
    /// Suspicious prefixes often used in typosquatting attacks.
    /// </summary>
    private static readonly string[] SuspiciousPrefixes =
        ["real-", "official-", "secure-", "safe-", "new-", "latest-"];

    /// <summary>
    /// Suspicious suffixes often used in typosquatting attacks.
    /// </summary>
    private static readonly string[] SuspiciousSuffixes =
        ["-official", "-secure", "-new", "-v2", "-pro"];

    /// <summary>
    /// Minimum similarity threshold for flagging potential typosquats.
    /// </summary>
    private const double SimilarityThreshold = 0.85;

    /// <summary>
    /// Maximum Levenshtein distance for potential typosquats.
    /// </summary>
    private const int MaxLevenshteinDistance = 3;

    /// <summary>
    /// Checks if a server name might be a typosquat of a known legitimate server.
    /// </summary>
    /// <param name="serverName">Server name to check.</param>
    /// <returns>Detection result with potential match information.</returns>
    /// <exception cref="ArgumentNullException">Thrown when serverName is null.</exception>
    public static TyposquatResult CheckForTyposquat(string serverName)
    {
        ArgumentNullException.ThrowIfNull(serverName);

        var normalizedName = NormalizeName(serverName);

        // Exact match is safe
        if (KnownLegitimateServers.Contains(normalizedName))
        {
            return new TyposquatResult
            {
                IsSuspicious = false,
                ServerName = serverName,
                MatchedLegitimateServer = normalizedName,
                Reason = "Exact match with known legitimate server"
            };
        }

        // Check Levenshtein distance to all known servers
        var levenshteinResult = CheckLevenshteinSimilarity(normalizedName, serverName);
        if (levenshteinResult is not null)
        {
            return levenshteinResult;
        }

        // Check for common typosquat patterns
        var patternResult = CheckTyposquatPatterns(normalizedName, serverName);
        if (patternResult is not null)
        {
            return patternResult;
        }

        return new TyposquatResult
        {
            IsSuspicious = false,
            ServerName = serverName,
            Reason = "No typosquat patterns detected"
        };
    }

    /// <summary>
    /// Adds a server name to the known legitimate list (for custom allowlists).
    /// </summary>
    /// <param name="serverName">The server name to add.</param>
    /// <exception cref="ArgumentNullException">Thrown when serverName is null.</exception>
    public static void AddLegitimateServer(string serverName)
    {
        ArgumentNullException.ThrowIfNull(serverName);
        KnownLegitimateServers.Add(NormalizeName(serverName));
    }

    /// <summary>
    /// Normalises a server name for comparison.
    /// </summary>
    private static string NormalizeName(string name)
    {
        return name.ToLowerInvariant()
            .Replace("_", "-")
            .Replace(" ", "-")
            .Trim();
    }

    /// <summary>
    /// Checks Levenshtein similarity against known servers.
    /// </summary>
    private static TyposquatResult? CheckLevenshteinSimilarity(string normalizedName, string originalName)
    {
        foreach (var legitimate in KnownLegitimateServers)
        {
            var distance = ComputeLevenshteinDistance(normalizedName.AsSpan(), legitimate.AsSpan());
            var maxLength = Math.Max(normalizedName.Length, legitimate.Length);
            var similarity = 1.0 - ((double)distance / maxLength);

            // High similarity but not exact = suspicious
            if (similarity >= SimilarityThreshold && distance > 0 && distance <= MaxLevenshteinDistance)
            {
                return new TyposquatResult
                {
                    IsSuspicious = true,
                    ServerName = originalName,
                    MatchedLegitimateServer = legitimate,
                    Distance = distance,
                    Similarity = similarity,
                    Reason = $"Server name is very similar to known legitimate server '{legitimate}' " +
                             $"(Levenshtein distance: {distance}, similarity: {similarity:P0})"
                };
            }
        }

        return null;
    }

    /// <summary>
    /// Checks for common typosquat patterns.
    /// </summary>
    private static TyposquatResult? CheckTyposquatPatterns(string normalizedName, string originalName)
    {
        // Check leet-speak substitutions
        var leetResult = CheckLeetSubstitutions(normalizedName, originalName);
        if (leetResult is not null)
        {
            return leetResult;
        }

        // Check prefix manipulations
        foreach (var prefix in SuspiciousPrefixes)
        {
            if (normalizedName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                var stripped = normalizedName[prefix.Length..];
                if (KnownLegitimateServers.Contains(stripped))
                {
                    return new TyposquatResult
                    {
                        IsSuspicious = true,
                        ServerName = originalName,
                        MatchedLegitimateServer = stripped,
                        Reason = $"Suspicious prefix '{prefix}' added to known legitimate server name"
                    };
                }
            }
        }

        // Check suffix manipulations
        foreach (var suffix in SuspiciousSuffixes)
        {
            if (normalizedName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                var stripped = normalizedName[..^suffix.Length];
                if (KnownLegitimateServers.Contains(stripped))
                {
                    return new TyposquatResult
                    {
                        IsSuspicious = true,
                        ServerName = originalName,
                        MatchedLegitimateServer = stripped,
                        Reason = $"Suspicious suffix '{suffix}' added to known legitimate server name"
                    };
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Checks for leet-speak substitutions.
    /// </summary>
    private static TyposquatResult? CheckLeetSubstitutions(string normalizedName, string originalName)
    {
        foreach (var (leet, normal) in LeetSubstitutions)
        {
            if (normalizedName.Contains(leet))
            {
                var deleeted = normalizedName.Replace(leet, normal);
                if (KnownLegitimateServers.Contains(deleeted))
                {
                    return new TyposquatResult
                    {
                        IsSuspicious = true,
                        ServerName = originalName,
                        MatchedLegitimateServer = deleeted,
                        Reason = $"Potential character substitution typosquat ('{leet}' -> '{normal}')"
                    };
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Computes the Levenshtein distance between two strings using an optimised
    /// single-row algorithm with Span for reduced allocations.
    /// </summary>
    /// <param name="source">The source string.</param>
    /// <param name="target">The target string.</param>
    /// <returns>The Levenshtein distance (minimum number of edits).</returns>
    private static int ComputeLevenshteinDistance(ReadOnlySpan<char> source, ReadOnlySpan<char> target)
    {
        var sourceLength = source.Length;
        var targetLength = target.Length;

        // Handle edge cases
        if (sourceLength == 0) return targetLength;
        if (targetLength == 0) return sourceLength;

        // Use stack allocation for small strings (performance optimisation)
        const int stackAllocThreshold = 256;
        Span<int> row0 = targetLength + 1 <= stackAllocThreshold
            ? stackalloc int[targetLength + 1]
            : new int[targetLength + 1];
        Span<int> row1 = targetLength + 1 <= stackAllocThreshold
            ? stackalloc int[targetLength + 1]
            : new int[targetLength + 1];

        // Initialise first row
        for (var j = 0; j <= targetLength; j++)
        {
            row0[j] = j;
        }

        // Compute distance
        for (var i = 1; i <= sourceLength; i++)
        {
            row1[0] = i;

            for (var j = 1; j <= targetLength; j++)
            {
                var cost = source[i - 1] == target[j - 1] ? 0 : 1;
                row1[j] = Math.Min(
                    Math.Min(row1[j - 1] + 1, row0[j] + 1),
                    row0[j - 1] + cost);
            }

            // Swap rows (can't use tuple deconstruction with Span)
            var temp = row0;
            row0 = row1;
            row1 = temp;
        }

        return row0[targetLength];
    }
}

/// <summary>
/// Result of typosquat detection analysis.
/// </summary>
public sealed record TyposquatResult
{
    /// <summary>
    /// Gets whether the server name is potentially a typosquat.
    /// </summary>
    public required bool IsSuspicious { get; init; }

    /// <summary>
    /// Gets the analysed server name.
    /// </summary>
    public required string ServerName { get; init; }

    /// <summary>
    /// Gets the legitimate server this may be impersonating, if any.
    /// </summary>
    public string? MatchedLegitimateServer { get; init; }

    /// <summary>
    /// Gets the Levenshtein distance to the matched server, if applicable.
    /// </summary>
    public int? Distance { get; init; }

    /// <summary>
    /// Gets the similarity score (0-1) to the matched server, if applicable.
    /// </summary>
    public double? Similarity { get; init; }

    /// <summary>
    /// Gets the human-readable reason for the detection result.
    /// </summary>
    public required string Reason { get; init; }
}
