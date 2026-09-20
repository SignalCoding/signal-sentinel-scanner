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
/// v3.0.0 (WP6): thin client for the OSV API. One <c>querybatch</c> POST (at most 100
/// packages) followed by bounded <c>GET /v1/vulns/{id}</c> detail fetches, because the
/// batch endpoint returns only ids. 10 second timeout per request, no retries — a failed
/// lookup degrades to SS-INFO-006, never to a scan failure. Only ever contacted when the
/// operator passed <c>--osv</c> and the scan is not offline.
/// </summary>
public sealed class OsvClient
{
    /// <summary>The fixed OSV batch endpoint; the scanner never takes it from user input.</summary>
    public const string QueryBatchUrl = "https://api.osv.dev/v1/querybatch";

    /// <summary>The fixed OSV detail endpoint prefix (id appended, URL-escaped).</summary>
    public const string VulnDetailUrlPrefix = "https://api.osv.dev/v1/vulns/";

    /// <summary>OSV querybatch accepts at most this many queries per request.</summary>
    public const int MaxPackagesPerRun = 100;

    /// <summary>Upper bound on detail fetches per run; ids beyond it keep the Medium default.</summary>
    public const int MaxDetailFetches = 60;

    private const int DetailConcurrency = 4;

    private const long MaxResponseBytes = 4 * 1024 * 1024;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static readonly TimeSpan DetailPhaseBudget = TimeSpan.FromSeconds(45);

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
        var http = new HttpClient(handler)
        {
            Timeout = Timeout,
            MaxResponseContentBufferSize = MaxResponseBytes
        };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(
            $"SignalSentinel.Scanner/{typeof(OsvClient).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"}");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        return new OsvClient(http);
    }

    /// <summary>
    /// Queries OSV for at most <see cref="MaxPackagesPerRun"/> pinned dependencies and
    /// returns the vulnerabilities found, enriched with summary/severity/aliases and
    /// collapsed so one advisory reported under several ids appears once per package.
    /// Throws on batch network/HTTP/parse failure; the caller converts that to a Failed
    /// surface. Individual detail-fetch failures fall back to the id-only record.
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

        string json;
        using (var response = await _httpClient.PostAsJsonAsync(
            QueryBatchUrl, payload, cancellationToken).ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();
            json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }

        var sparse = ParseQueryBatchResponse(json, pinnedDependencies);
        if (sparse.Count == 0)
        {
            return sparse;
        }

        var details = await FetchDetailsAsync(
            sparse.Select(v => v.Id).Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxDetailFetches).ToList(),
            cancellationToken).ConfigureAwait(false);

        return CollapseAliases(Enrich(sparse, details));
    }

    /// <summary>
    /// Parses a querybatch response body, pairing each result with the dependency that
    /// produced it by array position (the OSV contract). Malformed entries are skipped,
    /// never fatal.
    /// </summary>
    internal static IReadOnlyList<OsvVulnerability> ParseQueryBatchResponse(
        string json, IReadOnlyList<SkillDependency> queried)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
        if (doc.RootElement.ValueKind != JsonValueKind.Object
            || !doc.RootElement.TryGetProperty("results", out var results)
            || results.ValueKind != JsonValueKind.Array)
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
            if (result.ValueKind != JsonValueKind.Object
                || !result.TryGetProperty("vulns", out var vulns)
                || vulns.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var vuln in vulns.EnumerateArray())
            {
                if (vuln.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var id = GetString(vuln, "id");
                if (string.IsNullOrWhiteSpace(id) || id.Length > 64)
                {
                    continue;
                }

                var detail = ReadDetail(vuln);
                vulnerabilities.Add(new OsvVulnerability
                {
                    Id = id,
                    Summary = detail.Summary,
                    Severity = detail.Severity ?? Severity.Medium,
                    Aliases = detail.Aliases,
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

    /// <summary>
    /// Parses a <c>/v1/vulns/{id}</c> body (or an inline vuln object) into the fields the
    /// scanner reports. Returns null for a body that is not a JSON object.
    /// </summary>
    internal static OsvVulnDetail? ParseVulnDetail(string json)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
        return doc.RootElement.ValueKind == JsonValueKind.Object ? ReadDetail(doc.RootElement) : null;
    }

    /// <summary>
    /// Collapses vulnerabilities that describe the same advisory for the same package
    /// (e.g. a GHSA and a PYSEC record sharing one CVE alias) into a single entry,
    /// keeping the highest severity and preferring the record that carries a summary.
    /// </summary>
    internal static IReadOnlyList<OsvVulnerability> CollapseAliases(IReadOnlyList<OsvVulnerability> vulnerabilities)
    {
        ArgumentNullException.ThrowIfNull(vulnerabilities);

        return vulnerabilities
            .GroupBy(v => (v.SkillName, v.PackageName, v.PackageVersion, Key: CanonicalKey(v)),
                PackageKeyComparer.Instance)
            .Select(g =>
            {
                var ordered = g
                    .OrderByDescending(v => v.Severity)
                    .ThenByDescending(v => v.Summary.Length > 0)
                    .ThenBy(v => v.Id, StringComparer.Ordinal)
                    .ToList();
                var primary = ordered[0];
                var related = ordered
                    .SelectMany(v => v.Aliases.Append(v.Id))
                    .Where(a => !a.Equals(primary.Id, StringComparison.OrdinalIgnoreCase))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(a => a, StringComparer.Ordinal)
                    .ToList();
                return primary with { Aliases = related };
            })
            .ToList();
    }

    private static string CanonicalKey(OsvVulnerability v)
    {
        var cve = v.Aliases
            .Append(v.Id)
            .FirstOrDefault(a => a.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase));
        return (cve ?? v.Id).ToUpperInvariant();
    }

    private static List<OsvVulnerability> Enrich(
        IReadOnlyList<OsvVulnerability> sparse, IReadOnlyDictionary<string, OsvVulnDetail> details)
    {
        return sparse
            .Select(v => details.TryGetValue(v.Id, out var d)
                ? v with
                {
                    Summary = d.Summary.Length > 0 ? d.Summary : v.Summary,
                    Severity = d.Severity ?? v.Severity,
                    Aliases = d.Aliases.Count > 0 ? d.Aliases : v.Aliases
                }
                : v)
            .ToList();
    }

    private async Task<IReadOnlyDictionary<string, OsvVulnDetail>> FetchDetailsAsync(
        List<string> ids, CancellationToken cancellationToken)
    {
        var details = new Dictionary<string, OsvVulnDetail>(StringComparer.OrdinalIgnoreCase);
        if (ids.Count == 0)
        {
            return details;
        }

        // A bounded budget for the whole detail phase: whatever has not been fetched
        // when it expires simply keeps the id-only record and the Medium default.
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(DetailPhaseBudget);
        using var gate = new SemaphoreSlim(DetailConcurrency);
        var sync = new Lock();

        var tasks = ids.Select(async id =>
        {
            await gate.WaitAsync(budget.Token).ConfigureAwait(false);
            try
            {
                var detail = await FetchOneDetailAsync(id, budget.Token).ConfigureAwait(false);
                if (detail is not null)
                {
                    lock (sync)
                    {
                        details[id] = detail;
                    }
                }
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested
                && (ex is HttpRequestException or OperationCanceledException or JsonException
                    or InvalidOperationException or IOException))
            {
                // Per-id failure or budget expiry: fall back to the sparse record.
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return details;
    }

    private async Task<OsvVulnDetail?> FetchOneDetailAsync(string id, CancellationToken cancellationToken)
    {
        var url = new Uri(VulnDetailUrlPrefix + Uri.EscapeDataString(id));
        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ParseVulnDetail(json);
    }

    private static OsvVulnDetail ReadDetail(JsonElement vuln)
    {
        var summary = GetString(vuln, "summary") ?? string.Empty;
        var aliases = new List<string>();
        if (vuln.TryGetProperty("aliases", out var aliasArray) && aliasArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var alias in aliasArray.EnumerateArray())
            {
                if (alias.ValueKind == JsonValueKind.String
                    && alias.GetString() is { Length: > 0 and <= 64 } text
                    && aliases.Count < 16)
                {
                    aliases.Add(text);
                }
            }
        }

        return new OsvVulnDetail(Truncate(summary, 200), ReadSeverity(vuln), aliases);
    }

    private static Severity? ReadSeverity(JsonElement vuln)
    {
        // Preferred: CVSS v3 vector -> computed base score -> band.
        if (vuln.TryGetProperty("severity", out var severityArray) &&
            severityArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in severityArray.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object
                    && GetString(entry, "type") is "CVSS_V3"
                    && Cvss3.BaseScore(GetString(entry, "score")) is { } score)
                {
                    return Cvss3.ToSeverity(score);
                }
            }
        }

        // Fallback: the database's own band label (GitHub advisories carry one).
        if (vuln.TryGetProperty("database_specific", out var dbSpecific)
            && dbSpecific.ValueKind == JsonValueKind.Object
            && GetString(dbSpecific, "severity") is { Length: > 0 } label
            && label.All(char.IsLetter)
            && Enum.TryParse<Severity>(label, ignoreCase: true, out var banded)
            && Enum.IsDefined(banded))
        {
            return banded;
        }

        // Unknown: the caller applies the Medium default so a detail fetch can still improve it.
        return null;
    }

    private static string? GetString(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max];

    private sealed class PackageKeyComparer : IEqualityComparer<(string Skill, string Package, string Version, string Key)>
    {
        public static readonly PackageKeyComparer Instance = new();

        public bool Equals(
            (string Skill, string Package, string Version, string Key) x,
            (string Skill, string Package, string Version, string Key) y) =>
            string.Equals(x.Skill, y.Skill, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Package, y.Package, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Version, y.Version, StringComparison.Ordinal)
            && string.Equals(x.Key, y.Key, StringComparison.Ordinal);

        public int GetHashCode((string Skill, string Package, string Version, string Key) obj) =>
            HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Skill),
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Package),
                StringComparer.Ordinal.GetHashCode(obj.Version),
                StringComparer.Ordinal.GetHashCode(obj.Key));
    }
}
