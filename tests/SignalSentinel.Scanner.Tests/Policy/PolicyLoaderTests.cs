using System;
using System.IO;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Policy;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Policy;

public class PolicyLoaderTests
{
    [Fact]
    public void Resolve_Default_ReturnsEmptyPolicy()
    {
        PolicyLoader.TryResolve("default", out var policy, out var error).ShouldBeTrue();

        error.ShouldBeNull();
        policy.ShouldNotBeNull();
        policy.Name.ShouldBe("default");
        policy.IsEmpty.ShouldBeTrue();
    }

    [Fact]
    public void Resolve_Strict_BumpsSupplyChainRulesAndFailsOnMedium()
    {
        PolicyLoader.TryResolve("strict", out var policy, out _).ShouldBeTrue();

        var p = policy.ShouldNotBeNull();
        p.BumpOneBandRules.ShouldBe(
            ["SS-004", "SS-021", "SS-024", "SS-029", "SS-034", "SS-039"], ignoreOrder: true);
        p.BumpAllOneBand.ShouldBeFalse();
        p.FailOn.ShouldBe(Severity.Medium);
        p.ImpliesOffline.ShouldBeFalse();
        p.IsEmpty.ShouldBeFalse();
    }

    [Fact]
    public void Resolve_Defence_BumpsAllFailsOnLowImpliesOffline()
    {
        PolicyLoader.TryResolve("defence", out var policy, out _).ShouldBeTrue();

        var p = policy.ShouldNotBeNull();
        p.BumpAllOneBand.ShouldBeTrue();
        p.FailOn.ShouldBe(Severity.Low);
        p.ImpliesOffline.ShouldBeTrue();
    }

    [Fact]
    public void Resolve_PresetName_IsCaseInsensitive()
    {
        PolicyLoader.TryResolve("STRICT", out var policy, out _).ShouldBeTrue();

        policy.ShouldNotBeNull().FailOn.ShouldBe(Severity.Medium);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Resolve_NullOrWhitespace_Errors(string? arg)
    {
        PolicyLoader.TryResolve(arg!, out var policy, out var error).ShouldBeFalse();

        policy.ShouldBeNull();
        error.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Resolve_UnknownBareName_ErrorsListingPresets()
    {
        PolicyLoader.TryResolve("nosuchpreset", out _, out var error).ShouldBeFalse();

        error.ShouldNotBeNull().ShouldContain("strict");
        error.ShouldContain("defence");
    }

    [Fact]
    public void Resolve_MissingJsonPath_ErrorsNotFound()
    {
        PolicyLoader.TryResolve("nope-policy.json", out _, out var error).ShouldBeFalse();

        error.ShouldNotBeNull().ShouldContain("not found");
    }

    [Fact]
    public void Resolve_MalformedJson_Errors()
    {
        WithTempPolicyFile("{ not json", path =>
        {
            PolicyLoader.TryResolve(path, out _, out var error).ShouldBeFalse();
            error.ShouldNotBeNull().ShouldContain("JSON");
        });
    }

    [Fact]
    public void Resolve_InvalidSeverityOverride_Errors()
    {
        WithTempPolicyFile("""{ "severityOverrides": { "SS-024": "Bananas" } }""", path =>
        {
            PolicyLoader.TryResolve(path, out _, out var error).ShouldBeFalse();
            error.ShouldNotBeNull().ShouldContain("SS-024");
        });
    }

    [Theory]
    [InlineData("""{ "severityOverrides": { "SS-013": "3" } }""")]
    [InlineData("""{ "failOn": "4" }""")]
    public void Resolve_NumericSeverity_Errors(string json)
    {
        // Enum.TryParse would silently accept "3" as High; only alphabetic names are valid.
        WithTempPolicyFile(json, path =>
        {
            PolicyLoader.TryResolve(path, out _, out var error).ShouldBeFalse();
            error.ShouldNotBeNullOrWhiteSpace();
        });
    }

    [Fact]
    public void Resolve_InvalidFailOn_Errors()
    {
        WithTempPolicyFile("""{ "failOn": "sometimes" }""", path =>
        {
            PolicyLoader.TryResolve(path, out _, out var error).ShouldBeFalse();
            error.ShouldNotBeNull().ShouldContain("failOn");
        });
    }

    [Fact]
    public void Resolve_MinConfidenceOutOfRange_Errors()
    {
        WithTempPolicyFile("""{ "minConfidence": 1.5 }""", path =>
        {
            PolicyLoader.TryResolve(path, out _, out var error).ShouldBeFalse();
            error.ShouldNotBeNull().ShouldContain("minConfidence");
        });
    }

    [Fact]
    public void Resolve_CustomFile_RoundTripsAllFields()
    {
        const string json = """
            {
              "severityOverrides": { "ss-024": "High" },
              "disabledRules": [ "ss-info-005" ],
              "bumpOneBand": [ "SS-038" ],
              "failOn": "medium",
              "minConfidence": 0.5
            }
            """;

        WithTempPolicyFile(json, path =>
        {
            PolicyLoader.TryResolve(path, out var policy, out var error).ShouldBeTrue();

            error.ShouldBeNull();
            var p = policy.ShouldNotBeNull();
            p.Name.ShouldBe(path);
            p.SeverityOverrides.ShouldContainKeyAndValue("SS-024", Severity.High);
            p.DisabledRules.ShouldContain("SS-INFO-005");
            p.BumpOneBandRules.ShouldContain("SS-038");
            p.FailOn.ShouldBe(Severity.Medium);
            p.MinConfidence.ShouldBe(0.5);
            p.ImpliesOffline.ShouldBeFalse();
        });
    }

    [Fact]
    public void Resolve_CustomFile_RejectsUnreadablePath()
    {
        var directory = Path.GetTempPath();
        PolicyLoader.TryResolve(directory, out _, out var error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    private static void WithTempPolicyFile(string json, Action<string> assertion)
    {
        var path = Path.Combine(Path.GetTempPath(), $"sentinel-policy-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, json);
            assertion(path);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
