using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Osv;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Osv;

public class OsvLookupTests
{
    private static readonly SkillDefinition[] PipSkill =
        [TestSkills.MakeSkill("py-skill", "pip install requests==2.19.0")];

    [Fact]
    public async Task NotRequested_ExtractsWithoutQuerying()
    {
        var surface = await OsvLookup.BuildAsync(PipSkill, osvRequested: false, offline: false);

        surface.Status.ShouldBe(DependencyQueryStatus.NotRequested);
        surface.Dependencies.Count.ShouldBe(1);
        surface.QueriedCount.ShouldBe(0);
        surface.Vulnerabilities.ShouldBeEmpty();
    }

    [Fact]
    public async Task RequestedButOffline_NeverQueries()
    {
        var surface = await OsvLookup.BuildAsync(PipSkill, osvRequested: true, offline: true);

        surface.Status.ShouldBe(DependencyQueryStatus.Offline);
        surface.QueriedCount.ShouldBe(0);
    }

    [Fact]
    public async Task NoPinnedDependencies_SucceedsWithoutAQuery()
    {
        var skill = TestSkills.MakeSkill("skill", "pip install requests"); // unpinned

        var surface = await OsvLookup.BuildAsync(
            [skill], osvRequested: true, offline: false,
            queryOverride: (_, _) => throw new InvalidOperationException("should not be called"));

        surface.Status.ShouldBe(DependencyQueryStatus.Succeeded);
        surface.QueriedCount.ShouldBe(0);
        surface.Dependencies.Count.ShouldBe(1);
    }

    [Fact]
    public async Task PinnedDependencies_AreQueriedAndVulnsSurfaced()
    {
        var surface = await OsvLookup.BuildAsync(
            PipSkill, osvRequested: true, offline: false,
            queryOverride: (deps, _) =>
            {
                deps.Count.ShouldBe(1);
                deps[0].Name.ShouldBe("requests");
                deps[0].Version.ShouldBe("2.19.0");
                return Task.FromResult<IReadOnlyList<OsvVulnerability>>(
                [
                    new OsvVulnerability
                    {
                        Id = "GHSA-x", Summary = "test vuln", Severity = Severity.High,
                        Ecosystem = "PyPI", PackageName = "requests", PackageVersion = "2.19.0",
                        SkillName = "py-skill", Source = "instructions"
                    }
                ]);
            });

        surface.Status.ShouldBe(DependencyQueryStatus.Succeeded);
        surface.QueriedCount.ShouldBe(1);
        surface.Vulnerabilities.Count.ShouldBe(1);
        surface.Vulnerabilities[0].Id.ShouldBe("GHSA-x");
    }

    [Fact]
    public async Task DuplicateReferences_DeduplicatedPerSkill()
    {
        var skill = TestSkills.MakeSkill("skill", "pip install requests==2.19.0\npip3 install requests==2.19.0");

        var surface = await OsvLookup.BuildAsync([skill], osvRequested: false, offline: false);

        surface.Dependencies.Count.ShouldBe(1);
    }

    [Fact]
    public async Task SamePackageInTwoSkills_BothKept()
    {
        var skills = new[]
        {
            TestSkills.MakeSkill("skill-a", "pip install requests==2.19.0"),
            TestSkills.MakeSkill("skill-b", "pip install requests==2.19.0")
        };

        var surface = await OsvLookup.BuildAsync(skills, osvRequested: false, offline: false);

        surface.Dependencies.Count.ShouldBe(2);
    }

    [Fact]
    public async Task OverOneHundredPinned_TruncatesAtCap()
    {
        var instructions = string.Join('\n',
            Enumerable.Range(0, 150).Select(i => $"npm install pkg-{i}@1.0.0"));
        var skill = TestSkills.MakeSkill("big-skill", instructions);
        IReadOnlyList<SkillDependency>? queried = null;

        var surface = await OsvLookup.BuildAsync(
            [skill], osvRequested: true, offline: false,
            queryOverride: (deps, _) =>
            {
                queried = deps;
                return Task.FromResult<IReadOnlyList<OsvVulnerability>>([]);
            });

        surface.Truncated.ShouldBeTrue();
        surface.QueriedCount.ShouldBe(100);
        queried.ShouldNotBeNull().Count.ShouldBe(100);
    }

    [Fact]
    public async Task QueryFailure_FailedStatusWithReason()
    {
        var surface = await OsvLookup.BuildAsync(
            PipSkill, osvRequested: true, offline: false,
            queryOverride: (_, _) => Task.FromException<IReadOnlyList<OsvVulnerability>>(
                new HttpRequestException("connection refused")));

        surface.Status.ShouldBe(DependencyQueryStatus.Failed);
        surface.FailureReason.ShouldNotBeNull().ShouldContain("HttpRequestException");
        surface.Vulnerabilities.ShouldBeEmpty();
    }

    [Fact]
    public async Task HttpTimeout_IsAFailedLookup_NotACancelledScan()
    {
        // HttpClient surfaces its own timeout as TaskCanceledException; the scan token is untouched.
        var surface = await OsvLookup.BuildAsync(
            PipSkill, osvRequested: true, offline: false,
            queryOverride: (_, _) => Task.FromException<IReadOnlyList<OsvVulnerability>>(
                new TaskCanceledException("timed out", new TimeoutException())));

        surface.Status.ShouldBe(DependencyQueryStatus.Failed);
        surface.FailureReason.ShouldNotBeNull().ShouldContain("TaskCanceledException");
    }

    [Fact]
    public async Task OperatorCancellation_StillPropagates()
    {
        using var cts = new CancellationTokenSource();

        await Should.ThrowAsync<OperationCanceledException>(() => OsvLookup.BuildAsync(
            PipSkill, osvRequested: true, offline: false,
            queryOverride: (_, token) =>
            {
                cts.Cancel();
                return Task.FromCanceled<IReadOnlyList<OsvVulnerability>>(token);
            },
            cts.Token));
    }
}
