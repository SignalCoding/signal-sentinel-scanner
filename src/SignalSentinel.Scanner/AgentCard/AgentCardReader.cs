// -----------------------------------------------------------------------
// <copyright file="AgentCardReader.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using SignalSentinel.Scanner.Offline;

namespace SignalSentinel.Scanner.AgentCard;

/// <summary>
/// v3.0.0 (WP9): loads an A2A Agent Card from a URL or a local JSON file and reduces it
/// to <see cref="AgentCardAnalysis"/>. A bare origin gets <c>/.well-known/agent.json</c>
/// appended. Network reads honour <see cref="OfflineGuard"/>, use TLS 1.2+, a 10 s
/// timeout and a 1 MB body bound. Any failure degrades to a Failed analysis, never to a
/// scan error.
/// </summary>
public static class AgentCardReader
{
    /// <summary>The A2A discovery path appended to a bare origin.</summary>
    public const string WellKnownPath = "/.well-known/agent.json";

    /// <summary>Largest card body read from disk or network.</summary>
    public const long MaxCardBytes = 1024 * 1024;

    private const int MaxSkills = 100;

    private const int MaxTextLength = 20_000;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    /// <summary>True when <paramref name="target"/> is an http(s) URL rather than a file path.</summary>
    public static bool IsUrl(string target) =>
        Uri.TryCreate(target, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    /// <summary>
    /// Expands a bare origin (no path, or "/") to the well-known discovery URL; any other
    /// URL is returned as-is.
    /// </summary>
    public static string ExpandWellKnown(string target)
    {
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri))
        {
            return target;
        }

        return uri.AbsolutePath is "" or "/" && string.IsNullOrEmpty(uri.Query)
            ? new UriBuilder(uri) { Path = WellKnownPath, Query = string.Empty }.Uri.ToString()
            : target;
    }

    /// <summary>Loads and parses the card at <paramref name="target"/> (URL or path).</summary>
    public static Task<AgentCardAnalysis> LoadAsync(string target, CancellationToken cancellationToken = default) =>
        LoadAsync(target, httpClient: null, cancellationToken);

    /// <summary>Core implementation; tests inject <paramref name="httpClient"/>.</summary>
    internal static async Task<AgentCardAnalysis> LoadAsync(
        string target, HttpClient? httpClient, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);

        if (IsUrl(target))
        {
            var url = ExpandWellKnown(target);
            try
            {
                OfflineGuard.EnsureAllowed("A2A Agent Card fetch");
                var json = await FetchAsync(url, httpClient, cancellationToken).ConfigureAwait(false);
                return Parse(json, url, fromNetwork: true);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested && ex is not OutOfMemoryException)
            {
                return Failed(url, fromNetwork: true, ex.GetType().Name);
            }
        }

        try
        {
            var path = Path.GetFullPath(target);
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return Failed(path, fromNetwork: false, "FileNotFound");
            }

            if (info.Length == 0 || info.Length > MaxCardBytes)
            {
                return Failed(path, fromNetwork: false, "FileSizeOutOfBounds");
            }

            var json = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            return Parse(json, path, fromNetwork: false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested
            && ex is IOException or UnauthorizedAccessException or ArgumentException or JsonException
                or NotSupportedException or System.Security.SecurityException)
        {
            return Failed(target, fromNetwork: false, ex.GetType().Name);
        }
    }

    /// <summary>Parses a card body. Throws <see cref="JsonException"/> on malformed JSON.</summary>
    internal static AgentCardAnalysis Parse(string json, string source, bool fromNetwork)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32, AllowTrailingCommas = true });
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return Failed(source, fromNetwork, "NotAJsonObject");
        }

        var name = GetString(root, "name");
        var skills = new List<AgentCardSkill>();
        if (root.TryGetProperty("skills", out var skillArray) && skillArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var skill in skillArray.EnumerateArray())
            {
                if (skill.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                if (skills.Count >= MaxSkills)
                {
                    break;
                }

                var skillName = GetString(skill, "name") ?? GetString(skill, "id") ?? $"skill-{skills.Count + 1}";
                skills.Add(new AgentCardSkill(
                    skillName.Length <= 200 ? skillName : skillName[..200],
                    Bound(GetString(skill, "description"), MaxTextLength)));
            }
        }

        var declares = false;
        var schemesEmpty = false;
        if (root.TryGetProperty("securitySchemes", out var schemes))
        {
            if (schemes.ValueKind == JsonValueKind.Object)
            {
                declares = schemes.EnumerateObject().Any();
                schemesEmpty = !declares;
            }
            else if (schemes.ValueKind == JsonValueKind.Array)
            {
                declares = schemes.GetArrayLength() > 0;
                schemesEmpty = !declares;
            }
        }

        // Pre-1.0 cards used "authentication": { "schemes": [...] }.
        if (!declares && root.TryGetProperty("authentication", out var auth) && auth.ValueKind == JsonValueKind.Object
            && auth.TryGetProperty("schemes", out var legacy) && legacy.ValueKind == JsonValueKind.Array)
        {
            declares = legacy.GetArrayLength() > 0;
        }

        return new AgentCardAnalysis
        {
            Source = source,
            FromNetwork = fromNetwork,
            Status = AgentCardStatus.Loaded,
            DisplayName = Bound(name, 200) ?? FallbackName(source),
            Description = Bound(GetString(root, "description"), MaxTextLength),
            EndpointUrl = Bound(GetString(root, "url"), 2048),
            Skills = skills,
            DeclaresSecurityScheme = declares,
            SecuritySchemesEmpty = schemesEmpty
        };
    }

    private static async Task<string> FetchAsync(string url, HttpClient? injected, CancellationToken cancellationToken)
    {
        var client = injected ?? CreateDefaultClient();
        try
        {
            using var response = await client.GetAsync(new Uri(url), HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            if (response.Content.Headers.ContentLength is > MaxCardBytes)
            {
                throw new InvalidDataException("Agent Card exceeds the size bound.");
            }

            using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var buffer = new char[8192];
            var builder = new System.Text.StringBuilder();
            int read;
            while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
            {
                builder.Append(buffer, 0, read);
                if (builder.Length > MaxCardBytes)
                {
                    throw new InvalidDataException("Agent Card exceeds the size bound.");
                }
            }

            return builder.ToString();
        }
        finally
        {
            if (injected is null)
            {
                client.Dispose();
            }
        }
    }

    private static HttpClient CreateDefaultClient()
    {
        var handler = new HttpClientHandler
        {
            CheckCertificateRevocationList = true,
            AllowAutoRedirect = false,
#pragma warning disable CA5398 // TLS 1.2 is the floor, not the ceiling
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12
                | System.Security.Authentication.SslProtocols.Tls13,
#pragma warning restore CA5398
        };
        var http = new HttpClient(handler) { Timeout = Timeout, MaxResponseContentBufferSize = MaxCardBytes };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(
            $"SignalSentinel.Scanner/{typeof(AgentCardReader).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        return http;
    }

    private static AgentCardAnalysis Failed(string source, bool fromNetwork, string reason) =>
        new()
        {
            Source = source,
            FromNetwork = fromNetwork,
            Status = AgentCardStatus.Failed,
            FailureReason = reason,
            DisplayName = FallbackName(source)
        };

    private static string FallbackName(string source) =>
        Uri.TryCreate(source, UriKind.Absolute, out var uri) && !uri.IsFile
            ? uri.Host
            : Path.GetFileName(source) is { Length: > 0 } file ? file : source;

    private static string? GetString(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? Bound(string? value, int max) =>
        value is null ? null : value.Length <= max ? value : value[..max];
}
