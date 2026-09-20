using System.Collections.Generic;
using System.Linq;
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

    [Fact]
    public void MalformedEntries_SkippedNotFatal()
    {
        const string json = """
            {
              "results": [
                null,
                { "vulns": [
                    null,
                    "text",
                    { "id": 42 },
                    { "id": "" },
                    { "id": "GHSA-ok", "summary": 7,
                      "severity": [ null, "x", { "type": 1 }, { "type": "CVSS_V3", "score": 5 } ],
                      "database_specific": { "severity": 9 } },
                    { "id": "GHSA-label", "database_specific": "HIGH" },
                    { "id": "GHSA-num", "database_specific": { "severity": "3" } }
                ] }
              ]
            }
            """;

        var vulns = Should.NotThrow(() => OsvClient.ParseQueryBatchResponse(json, Deps));

        vulns.Count.ShouldBe(3);
        vulns.ShouldAllBe(v => v.PackageName == "lodash");
        vulns.ShouldAllBe(v => v.Severity == Severity.Medium);
        vulns[0].Summary.ShouldBe(string.Empty);
    }

    [Fact]
    public void RootArray_ReturnsEmpty()
    {
        OsvClient.ParseQueryBatchResponse("[]", Deps).ShouldBeEmpty();
    }

    [Fact]
    public void ParseVulnDetail_ReadsSummarySeverityAliases()
    {
        const string json = """
            {
              "id": "GHSA-x84v-xcm2-53pg",
              "summary": "Requests exposes credentials",
              "aliases": [ "CVE-2018-18074", "PYSEC-2018-28" ],
              "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" } ],
              "database_specific": { "severity": "MODERATE" }
            }
            """;

        var detail = OsvClient.ParseVulnDetail(json).ShouldNotBeNull();

        detail.Summary.ShouldBe("Requests exposes credentials");
        detail.Severity.ShouldBe(Severity.High);
        detail.Aliases.ShouldBe(["CVE-2018-18074", "PYSEC-2018-28"]);
    }

    [Fact]
    public void ParseVulnDetail_NoSeveritySource_ReturnsNullSeverity()
    {
        var detail = OsvClient.ParseVulnDetail("""{ "id": "PYSEC-1", "summary": "s" }""").ShouldNotBeNull();

        detail.Severity.ShouldBeNull();
        OsvClient.ParseVulnDetail("[]").ShouldBeNull();
    }

    [Fact]
    public void CollapseAliases_MergesRecordsSharingACve_KeepsHighestSeverity()
    {
        var ghsa = Make("GHSA-1", "requests", Severity.High, "credential leak", ["CVE-2018-18074"]);
        var pysec = Make("PYSEC-1", "requests", Severity.Critical, string.Empty, ["CVE-2018-18074", "GHSA-1"]);
        var unrelated = Make("GHSA-2", "requests", Severity.Low, "other", ["CVE-2020-1"]);
        var otherPackage = Make("GHSA-1", "lodash", Severity.High, "same id, other package", ["CVE-2018-18074"]);

        var collapsed = OsvClient.CollapseAliases([ghsa, pysec, unrelated, otherPackage]);

        collapsed.Count.ShouldBe(3);
        var merged = collapsed.Single(v => v.PackageName == "requests" && v.Aliases.Contains("CVE-2018-18074"));
        merged.Id.ShouldBe("PYSEC-1");
        merged.Severity.ShouldBe(Severity.Critical);
        merged.Aliases.ShouldBe(["CVE-2018-18074", "GHSA-1"]);
        collapsed.ShouldContain(v => v.Id == "GHSA-2");
        collapsed.ShouldContain(v => v.PackageName == "lodash");
    }

    [Fact]
    public void CollapseAliases_PrefersRecordWithSummaryOnSeverityTie()
    {
        var withSummary = Make("GHSA-1", "requests", Severity.High, "has text", ["CVE-1"]);
        var without = Make("PYSEC-1", "requests", Severity.High, string.Empty, ["CVE-1"]);

        var collapsed = OsvClient.CollapseAliases([without, withSummary]);

        collapsed.Count.ShouldBe(1);
        collapsed[0].Id.ShouldBe("GHSA-1");
    }

    [Fact]
    public void CollapseAliases_MergesWhenOnlyOneSideNamesTheOther()
    {
        // The PYSEC twin's detail fetch failed, so it carries no aliases of its own.
        var ghsa = Make("GHSA-1", "requests", Severity.High, "text", ["CVE-1", "PYSEC-1"]);
        var pysec = Make("PYSEC-1", "requests", Severity.Medium, string.Empty, []);
        var chained = Make("OSV-9", "requests", Severity.Low, string.Empty, ["PYSEC-1"]);

        var collapsed = OsvClient.CollapseAliases([pysec, chained, ghsa]);

        collapsed.Count.ShouldBe(1);
        collapsed[0].Id.ShouldBe("GHSA-1");
        collapsed[0].Aliases.ShouldBe(["CVE-1", "OSV-9", "PYSEC-1"]);
    }

    [Fact]
    public void CollapseAliases_NoSharedIdentifiers_KeepsAll()
    {
        var a = Make("GHSA-1", "requests", Severity.High, "a", []);
        var b = Make("GHSA-2", "requests", Severity.High, "b", []);

        OsvClient.CollapseAliases([a, b]).Count.ShouldBe(2);
    }

    private static OsvVulnerability Make(
        string id, string package, Severity severity, string summary, string[] aliases) =>
        new()
        {
            Id = id, Summary = summary, Severity = severity, Aliases = aliases,
            Ecosystem = "PyPI", PackageName = package, PackageVersion = "1.0",
            SkillName = "skill", Source = "instructions"
        };
}
