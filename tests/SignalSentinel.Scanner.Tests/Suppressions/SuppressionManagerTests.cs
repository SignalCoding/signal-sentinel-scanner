using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Suppressions;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Suppressions;

public class SuppressionManagerTests
{
    private static Finding MakeFinding(string ruleId, string serverName, string? toolName = null, string? evidence = null, string? skillPath = null)
    {
        return new Finding
        {
            RuleId = ruleId,
            OwaspCode = "ASI01",
            Severity = Severity.High,
            Title = "Test finding",
            Description = "d",
            Remediation = "r",
            ServerName = serverName,
            ToolName = toolName,
            Evidence = evidence,
            SkillFilePath = skillPath,
            Confidence = 0.9
        };
    }

    [Fact]
    public async Task LoadAsync_FileMissing_ReturnsNull()
    {
        var path = Path.Combine(Path.GetTempPath(), $"not-exist-{Guid.NewGuid()}.json");
        var file = await SuppressionManager.LoadAsync(path);
        Assert.Null(file);
    }

    [Fact]
    public async Task LoadAsync_ValidFile_ReturnsParsedSchema()
    {
        var path = Path.GetTempFileName() + ".json";
        try
        {
            await File.WriteAllTextAsync(path, "{\"version\":\"1.0\",\"suppressions\":[{\"ruleId\":\"SS-014\",\"justification\":\"ok\"}]}");
            var file = await SuppressionManager.LoadAsync(path);
            Assert.NotNull(file);
            Assert.Single(file!.Suppressions);
            Assert.Equal("SS-014", file.Suppressions[0].RuleId);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadAsync_MissingJustification_Throws()
    {
        var path = Path.GetTempFileName() + ".json";
        try
        {
            await File.WriteAllTextAsync(path, "{\"version\":\"1.0\",\"suppressions\":[{\"ruleId\":\"SS-014\"}]}");
            await Assert.ThrowsAsync<InvalidOperationException>(() => SuppressionManager.LoadAsync(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadAsync_MalformedJson_Throws()
    {
        var path = Path.GetTempFileName() + ".json";
        try
        {
            await File.WriteAllTextAsync(path, "{ not valid json");
            await Assert.ThrowsAsync<InvalidOperationException>(() => SuppressionManager.LoadAsync(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadAsync_UnsupportedVersion_Throws()
    {
        var path = Path.GetTempFileName() + ".json";
        try
        {
            await File.WriteAllTextAsync(path, "{\"version\":\"9.9\",\"suppressions\":[]}");
            await Assert.ThrowsAsync<InvalidOperationException>(() => SuppressionManager.LoadAsync(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Apply_NoSuppressions_ReturnsInputUnchanged()
    {
        var findings = new[] { MakeFinding("SS-014", "srv") };
        var result = SuppressionManager.Apply(findings, null, "default", DateTimeOffset.UtcNow);
        Assert.Same(findings, result);
    }

    [Fact]
    public void Apply_MatchingRuleId_AnnotatesSuppression()
    {
        var file = new SuppressionFile
        {
            Suppressions = new[]
            {
                new SuppressionEntry { RuleId = "SS-014", Justification = "Accepted risk", ApprovedBy = "alice@example.com" }
            }
        };
        var findings = new[] { MakeFinding("SS-014", "srv") };
        var result = SuppressionManager.Apply(findings, file, "default", DateTimeOffset.UtcNow);
        Assert.NotNull(result[0].Suppression);
        Assert.Equal("Accepted risk", result[0].Suppression!.Justification);
        Assert.False(result[0].Suppression!.Expired);
    }

    [Fact]
    public void Apply_RuleIdMismatch_LeavesFindingUnsuppressed()
    {
        var file = new SuppressionFile
        {
            Suppressions = new[] { new SuppressionEntry { RuleId = "SS-014", Justification = "ok" } }
        };
        var findings = new[] { MakeFinding("SS-015", "srv") };
        var result = SuppressionManager.Apply(findings, file, "default", DateTimeOffset.UtcNow);
        Assert.Null(result[0].Suppression);
    }

    [Fact]
    public void Apply_MultipleCriteriaAnd_MustAllMatch()
    {
        var file = new SuppressionFile
        {
            Suppressions = new[]
            {
                new SuppressionEntry
                {
                    RuleId = "SS-014",
                    ServerName = "serverA",
                    Evidence = "fetch(",
                    Justification = "English verb in quoted docs"
                }
            }
        };
        var matching = MakeFinding("SS-014", "serverA", evidence: "fetch(");
        var different = MakeFinding("SS-014", "serverB", evidence: "fetch(");
        var result = SuppressionManager.Apply(new[] { matching, different }, file, "default", DateTimeOffset.UtcNow);
        Assert.NotNull(result[0].Suppression);
        Assert.Null(result[1].Suppression);
    }

    [Fact]
    public void Apply_ExpiredSuppression_MarkedExpired()
    {
        var file = new SuppressionFile
        {
            Suppressions = new[]
            {
                new SuppressionEntry
                {
                    RuleId = "SS-014",
                    Justification = "old",
                    ExpiresOn = DateTimeOffset.UtcNow.AddDays(-1)
                }
            }
        };
        var result = SuppressionManager.Apply(new[] { MakeFinding("SS-014", "srv") }, file, "default", DateTimeOffset.UtcNow);
        Assert.NotNull(result[0].Suppression);
        Assert.True(result[0].Suppression!.Expired);
    }

    [Fact]
    public void Apply_EnvironmentScope_RespectsEnvironment()
    {
        var file = new SuppressionFile
        {
            Suppressions = new[]
            {
                new SuppressionEntry
                {
                    RuleId = "SS-014",
                    Environment = "dev",
                    Justification = "dev only"
                }
            }
        };
        var inDev = SuppressionManager.Apply(new[] { MakeFinding("SS-014", "srv") }, file, "dev", DateTimeOffset.UtcNow);
        var inProd = SuppressionManager.Apply(new[] { MakeFinding("SS-014", "srv") }, file, "prod", DateTimeOffset.UtcNow);
        Assert.NotNull(inDev[0].Suppression);
        Assert.Null(inProd[0].Suppression);
    }

    [Fact]
    public async Task SaveAsync_RoundTrip_Preserves()
    {
        var path = Path.GetTempFileName() + ".json";
        try
        {
            var file = new SuppressionFile
            {
                Suppressions = new[]
                {
                    new SuppressionEntry
                    {
                        RuleId = "SS-020",
                        ServerName = "openclaw-vucp",
                        Justification = "Traefik geo-fence + basic auth + rate-limit",
                        ApprovedBy = "security@example.com",
                        ApprovedOn = new DateTimeOffset(2026, 4, 17, 0, 0, 0, TimeSpan.Zero),
                        ExpiresOn = new DateTimeOffset(2026, 10, 17, 0, 0, 0, TimeSpan.Zero)
                    }
                }
            };
            await SuppressionManager.SaveAsync(path, file);
            var loaded = await SuppressionManager.LoadAsync(path);
            Assert.NotNull(loaded);
            Assert.Single(loaded!.Suppressions);
            Assert.Equal("SS-020", loaded.Suppressions[0].RuleId);
            Assert.Equal("openclaw-vucp", loaded.Suppressions[0].ServerName);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Append_AddsEntryToExistingList()
    {
        var start = new SuppressionFile
        {
            Suppressions = new[] { new SuppressionEntry { RuleId = "SS-001", Justification = "existing" } }
        };
        var appended = SuppressionManager.Append(start, new SuppressionEntry { RuleId = "SS-002", Justification = "new" });
        Assert.Equal(2, appended.Suppressions.Count);
        Assert.Equal("SS-002", appended.Suppressions[1].RuleId);
    }
}
