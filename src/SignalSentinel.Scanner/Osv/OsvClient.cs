// -----------------------------------------------------------------------
// <copyright file="OsvClient.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Net.Http.Json;
using System.Text.Json;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Offline;

namespace SignalSentinel.Scanner.Osv;

/// <summary>
/// v3.0.0 (WP6): thin client for the OSV querybatch API. One POST per call, at most
/// 100 packages, 10 second timeout, no retries — a failed lookup degrades to
/// SS-INFO-006, never to a scan failure. Only ever contacted when the operator passed
/// <c>--osv</c> and the scan is not offline.
/// </summary>
public sealed class OsvClient
{
    /// <summary>The fixed OSV endpoint; the scanner never takes it from user input.</summary>
    public const string QueryBatchUrl = "https://api.osv.dev/v1/querybatch";

    /// <summary>OSV querybatch accepts at most this many queries per request.</summary>
    public const int MaxPackagesPerRun = 100;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private readonly HttpClient _httpClient;

    public OsvClient(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    /// <summary>Creates a purpose-built client: TLS revocation checking, 10 s timeout, UA set.</summary>
    public static OsvClient CreateDefault()
    {
        OfflineGuard.EnsureAllowed("OSV vulnerability lookup");

        var handler = new HttpClientHandler
        {
            CheckCertificateRevocationList = true,
#pragma warning disable CA5398 // TLS 1.2 is the floor, not the ceiling
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12
                | System.Security.Authentication.SslProtocols.Tls13,
#pragma warning restore CA5398
        };
        var http = new HttpClient(handler) { Timeout = Timeout };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(
            $"SignalSentinel.Scanner/{typeof(OsvClient).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        return new OsvClient(http);
    }

    /// <summary>
    /// Queries OSV for at most <see cref="MaxPackagesPerRun"/> pinned dependencies and
    /// returns the vulnerabilities found. Throws on network/HTTP/parse failure; the
    /// caller converts that to a Failed surface.
    /// </summary>
    public async Task<IReadOnlyList<OsvVulnerability>> QueryAsync(
        IReadOnlyList<SkillDependency> pinnedDependencies,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pinnedDependencies);
        if (pinnedDependencies.Count == 0)
        {
            return [];
        }

        if (pinnedDependencies.Count > MaxPackagesPerRun)
        {
            throw new ArgumentException(
                $"At most {MaxPackagesPerRun} packages per lookup.", nameof(pinnedDependencies));
        }

        OfflineGuard.EnsureAllowed("OSV vulnerability lookup");

        var payload = new
        {
            queries = pinnedDependencies.Select(d => new
            {
                package = new { name = d.Name, ecosystem = d.Ecosystem },
                version = d.Version
            })
        };

        using var response = await _httpClient.PostAsJsonAsync(
            QueryBatchUrl, payload, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ParseQueryBatchResponse(json, pinnedDependencies);
    }

    /// <summary>
    /// Parses a querybatch response body, pairing each result with the dependency that
    /// produced it by array position (the OSV contract).
    /// </summary>
    internal static IReadOnlyList<OsvVulnerability> ParseQueryBatchResponse(
        string json, IReadOnlyList<SkillDependency> queried)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
        if (!doc.RootElement.TryGetProperty("results", out var results) ||
            results.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var vulnerabilities = new List<OsvVulnerability>();
        var index = 0;
        foreach (var result in results.EnumerateArray())
        {
            if (index >= queried.Count)
            {
                break;
            }

            var dependency = queried[index++];
            if (!result.TryGetProperty("vulns", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var vuln in vulns.EnumerateArray())
            {
                var id = vuln.TryGetProperty("id", out var idElement) &&
                    idElement.ValueKind == JsonValueKind.String
                        ? idElement.GetString()!
                        : "unknown";

                var summary = vuln.TryGetProperty("summary", out var summaryElement) &&
                    summaryElement.ValueKind == JsonValueKind.String
                        ? Truncate(summaryElement.GetString()!, 200)
                        : string.Empty;

                vulnerabilities.Add(new OsvVulnerability
                {
                    Id = id,
                    Summary = summary,
                    Severity = ReadSeverity(vuln),
                    Ecosystem = dependency.Ecosystem,
                    PackageName = dependency.Name,
                    PackageVersion = dependency.Version!,
                    SkillName = dependency.SkillName,
                    Source = dependency.Source
                });
            }
        }

        return vulnerabilities;
    }

    private static Severity ReadSeverity(JsonElement vuln)
    {
        // Preferred: CVSS v3 vector -> computed base score -> band.
        if (vuln.TryGetProperty("severity", out var severityArray) &&
            severityArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in severityArray.EnumerateArray())
            {
                if (entry.TryGetProperty("type", out var typeElement) &&
                    typeElement.GetString() is "CVSS_V3" &&
                    entry.TryGetProperty("score", out var scoreElement))
                {
                    var score = Cvss3.BaseScore(scoreElement.GetString());
                    if (score is not null)
                    {
                        return Cvss3.ToSeverity(score.Value);
                    }
                }
            }
        }

        // Fallback: the database's own band label (GitHub advisories carry one).
        if (vuln.TryGetProperty("database_specific", out var dbSpecific) &&
            dbSpecific.TryGetProperty("severity", out var label) &&
            Enum.TryParse<Severity>(label.GetString(), ignoreCase: true, out var banded) &&
            Enum.IsDefined(banded))
        {
            return banded;
        }

        // Unknown severity still deserves a look; report Medium rather than dropping it.
        return Severity.Medium;
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max];
}
