// -----------------------------------------------------------------------
// <copyright file="AuthProbeService.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Net;
using System.Text;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Network;
using SignalSentinel.Scanner.Offline;

namespace SignalSentinel.Scanner.McpClient;

/// <summary>
/// v2.4.0 (A2): performs a deliberate unauthenticated MCP initialize request
/// against a remote HTTP / Streamable-HTTP / WebSocket target so downstream rules
/// can classify whether the server enforces authentication based on observed
/// behaviour rather than the operator's config shape.
/// </summary>
/// <remarks>
/// <para>
/// Design rationale: prior to v2.4.0 the OAuth-compliance rule introspected
/// <see cref="McpServerConfig.Env"/> to decide whether a "no auth" finding should
/// fire. This produced false positives once the scanner grew support for the
/// <c>headers</c> config field (v2.3.1) - a server fronted by OAuth Bearer would
/// legitimately have no auth-named env var but still demonstrably enforce auth.
/// </para>
/// <para>
/// The correct question is "does the server demand credentials?", which is
/// answered by sending one request without them.
/// </para>
/// </remarks>
public static class AuthProbeService
{
    private const int MaxWwwAuthenticateLength = 4096;
    private const string InitializeBody =
        "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":" +
        "{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{}," +
        "\"clientInfo\":{\"name\":\"signal-sentinel-scanner-auth-probe\",\"version\":\"1.0\"}}," +
        "\"id\":0}";

    /// <summary>
    /// Sends one unauthenticated POST to the target URL and classifies the response.
    /// Returns <see langword="null"/> for transports that are not probeable
    /// (stdio) or inputs that cannot be parsed.
    /// </summary>
    public static async Task<AuthProbeResult?> ProbeAsync(
        McpServerConfig config,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(config);

        // Only remote HTTP / WebSocket-style transports are probeable in this way.
        // WebSocket probing would need a separate HTTP upgrade handshake; skip for
        // v2.4.0 and treat as not-probed.
        if (config.Transport is not (McpTransportType.Http or McpTransportType.StreamableHttp))
        {
            return null;
        }
        if (string.IsNullOrWhiteSpace(config.Url))
        {
            return null;
        }
        if (!Uri.TryCreate(config.Url, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https"))
        {
            return null;
        }

        // Defence-in-depth: do not probe non-public targets. They are either on a
        // trusted tunnel (loopback) or deliberately non-routable; firing an extra
        // request changes no signal and only adds noise. The downstream rule also
        // exempts non-public targets so the probe result would be unused.
        var classification = NonPublicTarget.Classify(uri);
        if (NonPublicTarget.IsNonPublic(classification))
        {
            return null;
        }

        OfflineGuard.EnsureAllowed($"Auth probe to {config.Url}");

        // Purpose-built HttpClient for the probe. No Authorization header, no
        // operator-supplied Headers dictionary. User-Agent identifies the probe
        // so server-side observers can tell this apart from a real client.
        using var handler = new HttpClientHandler
        {
            CheckCertificateRevocationList = true,
#pragma warning disable CA5398
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12
                | System.Security.Authentication.SslProtocols.Tls13,
#pragma warning restore CA5398
        };
        using var client = new HttpClient(handler) { Timeout = timeout };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(
            "SignalSentinelScanner/AuthProbe (+https://signalcoding.co.uk)");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        client.DefaultRequestHeaders.Accept.ParseAdd("text/event-stream");

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, uri)
            {
                Content = new StringContent(InitializeBody, Encoding.UTF8, "application/json"),
            };
            using var resp = await client.SendAsync(
                req,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            var code = (int)resp.StatusCode;
            var www = ExtractWwwAuthenticate(resp);

            if (resp.StatusCode == HttpStatusCode.Unauthorized)
            {
                var challengeIsBearer = www is not null &&
                    www.Contains("bearer", StringComparison.OrdinalIgnoreCase);
                return new AuthProbeResult
                {
                    StatusCode = code,
                    WwwAuthenticate = www,
                    AnonymousInitializeSucceeded = false,
                    AuthEnforced = challengeIsBearer,
                    Classification = challengeIsBearer ? "enforced" : "unclear",
                    Note = challengeIsBearer
                        ? null
                        : "401 returned but WWW-Authenticate header did not advertise Bearer.",
                };
            }

            if (resp.IsSuccessStatusCode)
            {
                // A 2xx without auth means the server accepted an anonymous MCP
                // initialize. That is the exact definition of "open".
                return new AuthProbeResult
                {
                    StatusCode = code,
                    WwwAuthenticate = www,
                    AnonymousInitializeSucceeded = true,
                    AuthEnforced = false,
                    Classification = "open",
                };
            }

            // Any other status code (403 / 404 / 5xx): we can't tell whether auth
            // would gate access or the endpoint simply doesn't exist at this path.
            return new AuthProbeResult
            {
                StatusCode = code,
                WwwAuthenticate = www,
                AnonymousInitializeSucceeded = false,
                AuthEnforced = false,
                Classification = "unclear",
                Note = $"Unexpected status {code} on unauthenticated probe.",
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.IO.IOException)
        {
            return new AuthProbeResult
            {
                StatusCode = 0,
                WwwAuthenticate = null,
                AnonymousInitializeSucceeded = false,
                AuthEnforced = false,
                Classification = "unclear",
                Note = $"Probe failed: {ex.GetType().Name}.",
            };
        }
    }

    private static string? ExtractWwwAuthenticate(HttpResponseMessage resp)
    {
        if (!resp.Headers.TryGetValues("WWW-Authenticate", out var values))
        {
            return null;
        }
        var joined = string.Join(", ", values);
        if (joined.Length > MaxWwwAuthenticateLength)
        {
            joined = joined[..MaxWwwAuthenticateLength];
        }
        // Strip control chars for safe display / logging.
        return new string([.. joined.Where(c => !char.IsControl(c))]);
    }
}
