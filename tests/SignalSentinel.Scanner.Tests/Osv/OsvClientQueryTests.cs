using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Osv;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Osv;

/// <summary>End-to-end <see cref="OsvClient.QueryAsync"/> against a scripted HTTP handler.</summary>
public class OsvClientQueryTests
{
    private static readonly IReadOnlyList<SkillDependency> Requests =
    [
        new SkillDependency
        {
            Name = "requests", Version = "2.19.0", Ecosystem = "PyPI",
            Source = "instructions", SkillName = "skill-a"
        }
    ];

    private const string SparseBatch = """
        { "results": [ { "vulns": [
            { "id": "GHSA-x84v-xcm2-53pg", "modified": "2024-01-01T00:00:00Z" },
            { "id": "PYSEC-2018-28", "modified": "2024-01-01T00:00:00Z" },
            { "id": "GHSA-9hjg-9r4m-mvj7", "modified": "2024-01-01T00:00:00Z" }
        ] } ] }
        """;

    [Fact]
    public async Task QueryAsync_EnrichesSparseBatchFromDetailEndpoint_AndCollapsesAliases()
    {
        using var handler = new ScriptedHandler(request =>
        {
            var url = request.RequestUri!.ToString();
            if (url == OsvClient.QueryBatchUrl)
            {
                request.Method.ShouldBe(HttpMethod.Post);
                return Json(SparseBatch);
            }

            return url switch
            {
                OsvClient.VulnDetailUrlPrefix + "GHSA-x84v-xcm2-53pg" => Json("""
                    { "id": "GHSA-x84v-xcm2-53pg", "summary": "Credential leak", "aliases": ["CVE-2018-18074", "PYSEC-2018-28"],
                      "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" } ] }
                    """),
                OsvClient.VulnDetailUrlPrefix + "PYSEC-2018-28" => Json("""
                    { "id": "PYSEC-2018-28", "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"] }
                    """),
                OsvClient.VulnDetailUrlPrefix + "GHSA-9hjg-9r4m-mvj7" => Json("""
                    { "id": "GHSA-9hjg-9r4m-mvj7", "summary": "Other issue", "database_specific": { "severity": "LOW" } }
                    """),
                _ => new HttpResponseMessage(HttpStatusCode.NotFound)
            };
        });
        using var http = new HttpClient(handler);
        var client = new OsvClient(http);

        var vulns = await client.QueryAsync(Requests);

        vulns.Count.ShouldBe(2);
        var leak = vulns.Single(v => v.Id == "GHSA-x84v-xcm2-53pg");
        leak.Severity.ShouldBe(Severity.High);
        leak.Summary.ShouldBe("Credential leak");
        leak.Aliases.ShouldBe(["CVE-2018-18074", "PYSEC-2018-28"]);
        var other = vulns.Single(v => v.Id == "GHSA-9hjg-9r4m-mvj7");
        other.Severity.ShouldBe(Severity.Low);
        handler.Requests.Count(u => u.StartsWith(OsvClient.VulnDetailUrlPrefix, StringComparison.Ordinal)).ShouldBe(3);
    }

    [Fact]
    public async Task QueryAsync_DetailFailure_FallsBackToSparseRecord()
    {
        using var handler = new ScriptedHandler(request =>
            request.RequestUri!.ToString() == OsvClient.QueryBatchUrl
                ? Json("""{ "results": [ { "vulns": [ { "id": "GHSA-only" } ] } ] }""")
                : throw new HttpRequestException("detail endpoint down"));
        using var http = new HttpClient(handler);
        var client = new OsvClient(http);

        var vulns = await client.QueryAsync(Requests);

        vulns.Count.ShouldBe(1);
        vulns[0].Id.ShouldBe("GHSA-only");
        vulns[0].Severity.ShouldBe(Severity.Medium);
        vulns[0].Summary.ShouldBe(string.Empty);
    }

    [Fact]
    public async Task QueryAsync_BatchHttpError_Throws()
    {
        using var handler = new ScriptedHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var http = new HttpClient(handler);
        var client = new OsvClient(http);

        await Should.ThrowAsync<HttpRequestException>(() => client.QueryAsync(Requests));
    }

    [Fact]
    public async Task QueryAsync_EmptyBatch_NoDetailFetches()
    {
        using var handler = new ScriptedHandler(_ => Json("""{ "results": [ { "vulns": [] } ] }"""));
        using var http = new HttpClient(handler);
        var client = new OsvClient(http);

        var vulns = await client.QueryAsync(Requests);

        vulns.ShouldBeEmpty();
        handler.Requests.Count.ShouldBe(1);
    }

    [Fact]
    public async Task QueryAsync_OverCap_Rejected()
    {
        var deps = Enumerable.Range(0, OsvClient.MaxPackagesPerRun + 1)
            .Select(i => Requests[0] with { Name = $"pkg-{i}" })
            .ToList();
        using var handler = new ScriptedHandler(_ => Json("{}"));
        using var http = new HttpClient(handler);
        var client = new OsvClient(http);

        await Should.ThrowAsync<ArgumentException>(() => client.QueryAsync(deps));
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };

    private sealed class ScriptedHandler(Func<HttpRequestMessage, HttpResponseMessage> script) : HttpMessageHandler
    {
        private readonly List<string> _requests = [];

        public List<string> Requests
        {
            get
            {
                lock (_requests)
                {
                    return _requests.ToList();
                }
            }
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (_requests)
            {
                _requests.Add(request.RequestUri!.ToString());
            }

            return Task.FromResult(script(request));
        }
    }
}
