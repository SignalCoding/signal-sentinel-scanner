using System;
using System.IO;
using System.Threading.Tasks;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.History;
using Xunit;

namespace SignalSentinel.Scanner.Tests.History;

/// <summary>
/// Regression: v2.2 JSON scan reports (lowercase severity strings) must be
/// loadable by the v2.3 diff command. This was caught during the OpenClaw
/// scan run on 2026-04-18 - the enum converter had to be added to
/// ScanHistoryManager.JsonOptions.
/// </summary>
public class ScanHistoryManagerRoundTripTests
{
    [Fact]
    public async Task LoadAsync_LowercaseSeverityJson_DeserializesCorrectly()
    {
        var path = Path.GetTempFileName() + ".json";
        try
        {
            var json = """
            {
              "scanTimestamp": "2026-04-17T17:27:24.7634223+00:00",
              "scannerVersion": "2.2.0",
              "servers": [],
              "findings": [
                {
                  "ruleId": "SS-011",
                  "owaspCode": "ASI01",
                  "severity": "high",
                  "title": "Test",
                  "description": "d",
                  "remediation": "r",
                  "serverName": "test-skill",
                  "evidence": "must ",
                  "confidence": 0.85,
                  "source": "skill"
                },
                {
                  "ruleId": "SS-014",
                  "owaspCode": "ASI09",
                  "severity": "critical",
                  "title": "Test2",
                  "description": "d",
                  "remediation": "r",
                  "serverName": "test-skill",
                  "evidence": "fetch (",
                  "confidence": 0.85,
                  "source": "skill"
                }
              ],
              "attackPaths": [],
              "grade": "F",
              "score": 24,
              "statistics": { "totalServers": 0 }
            }
            """;
            await File.WriteAllTextAsync(path, json);

            var loaded = await ScanHistoryManager.LoadAsync(path);

            Assert.NotNull(loaded);
            Assert.Equal("2.2.0", loaded!.ScannerVersion);
            Assert.Equal(2, loaded.Findings.Count);
            Assert.Equal(Severity.High, loaded.Findings[0].Severity);
            Assert.Equal(Severity.Critical, loaded.Findings[1].Severity);
            Assert.Equal(SecurityGrade.F, loaded.Grade);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_PascalCaseSeverityJson_DeserializesCorrectly()
    {
        // Defensive: allowIntegerValues=true + camelCase mapping should also
        // tolerate PascalCase produced by older tooling.
        var path = Path.GetTempFileName() + ".json";
        try
        {
            await File.WriteAllTextAsync(path, """
            {
              "scanTimestamp": "2026-04-18T10:00:00.0000000+00:00",
              "scannerVersion": "2.3.0",
              "servers": [],
              "findings": [
                {
                  "ruleId": "SS-999",
                  "owaspCode": "ASI01",
                  "severity": "Medium",
                  "title": "t",
                  "description": "d",
                  "remediation": "r",
                  "serverName": "x"
                }
              ],
              "attackPaths": [],
              "grade": "B",
              "score": 90,
              "statistics": { "totalServers": 0 }
            }
            """);

            var loaded = await ScanHistoryManager.LoadAsync(path);
            Assert.NotNull(loaded);
            Assert.Equal(Severity.Medium, loaded!.Findings[0].Severity);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task SaveAndLoad_RoundTripsFullResult()
    {
        var path = Path.GetTempFileName() + ".json";
        try
        {
            var result = new ScanResult
            {
                ScanTimestamp = new DateTimeOffset(2026, 4, 18, 10, 0, 0, TimeSpan.Zero),
                ScannerVersion = "2.3.0",
                Servers = Array.Empty<ServerScanSummary>(),
                Findings = new[]
                {
                    new Finding
                    {
                        RuleId = "SS-011",
                        OwaspCode = "ASI01",
                        Severity = Severity.High,
                        Title = "t",
                        Description = "d",
                        Remediation = "r",
                        ServerName = "srv",
                        Evidence = "e"
                    }
                },
                AttackPaths = Array.Empty<AttackPath>(),
                Grade = SecurityGrade.C,
                Score = 75,
                Statistics = new ScanStatistics()
            };

            var tempDir = Path.GetDirectoryName(path)!;
            var savedPath = await ScanHistoryManager.SaveAsync(result, tempDir);
            try
            {
                var loaded = await ScanHistoryManager.LoadAsync(savedPath);
                Assert.Equal(result.ScannerVersion, loaded.ScannerVersion);
                Assert.Equal(result.Grade, loaded.Grade);
                Assert.Equal(Severity.High, loaded.Findings[0].Severity);
            }
            finally
            {
                if (File.Exists(savedPath)) File.Delete(savedPath);
            }
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
