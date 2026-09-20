using System.Collections.Generic;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Osv;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Osv;

public class OsvClientResponseTests
{
    private static readonly IReadOnlyList<SkillDependency> Deps =
    [
        new SkillDependency
        {
            Name = "requests", Version = "2.19.0", Ecosystem = "PyPI",
            Source = "instructions", SkillName = "skill-a"
        },
        new SkillDependency
        {
            Name = "lodash", Version = "4.17.20", Ecosystem = "npm",
            Source = "package.json", SkillName = "skill-b"
        }
    ];

    [Fact]
    public void ParsesVulns_PairedByPosition()
    {
        const string json = """
            {
              "results": [
                { "vulns": [ { "id": "GHSA-jfm5-9jc6-28v3", "summary": "requests vuln",
                    "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ] } ] },
                { "vulns": [ { "id": "GHSA-35jh-r3h4-6jhm", "summary": "lodash prototype pollution" } ] }
              ]
            }
            """;

        var vulns = OsvClient.ParseQueryBatchResponse(json, Deps);

        vulns.Count.ShouldBe(2);
        vulns[0].Id.ShouldBe("GHSA-jfm5-9jc6-28v3");
        vulns[0].PackageName.ShouldBe("requests");
        vulns[0].PackageVersion.ShouldBe("2.19.0");
        vulns[0].SkillName.ShouldBe("skill-a");
        vulns[0].Severity.ShouldBe(Severity.Critical);
        vulns[1].Id.ShouldBe("GHSA-35jh-r3h4-6jhm");
        vulns[1].PackageName.ShouldBe("lodash");
        vulns[1].SkillName.ShouldBe("skill-b");
        vulns[1].Severity.ShouldBe(Severity.Medium); // no vector -> default Medium
    }

    [Fact]
    public void SeverityFallsBackToDatabaseSpecificLabel()
    {
        const string json = """
            {
              "results": [
                { "vulns": [ { "id": "PYSEC-1", "database_specific": { "severity": "HIGH" } } ] },
                { "vulns": [] }
              ]
            }
            """;

        var vulns = OsvClient.ParseQueryBatchResponse(json, Deps);

        vulns.Count.ShouldBe(1);
        vulns[0].Severity.ShouldBe(Severity.High);
    }

    [Fact]
    public void MissingResultsOrEmptyVulns_ReturnEmpty()
    {
        OsvClient.ParseQueryBatchResponse("{}", Deps).ShouldBeEmpty();
        OsvClient.ParseQueryBatchResponse(
            """{"results":[{"vulns":[]},{"vulns":[]}]}""", Deps)
            .ShouldBeEmpty();
    }

    [Fact]
    public void ExtraResultsBeyondQueried_AreBounded()
    {
        const string json = """
            { "results": [ {"vulns":[]}, {"vulns":[]}, {"vulns":[{"id":"X-1"}]} ] }
            """;

        var vulns = OsvClient.ParseQueryBatchResponse(json, Deps);

        vulns.ShouldBeEmpty();
    }
}
