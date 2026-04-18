// -----------------------------------------------------------------------
// <copyright file="SarifReportGenerator.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using System.Text.Json;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Reports;

/// <summary>
/// Produces scan output in SARIF v2.1.0 format for GitHub Code Scanning,
/// VS Code, Azure DevOps, and other SARIF-compatible tooling.
/// Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
/// </summary>
public sealed class SarifReportGenerator : IReportGenerator
{
    private const string SarifSchemaUri = "https://json.schemastore.org/sarif-2.1.0.json";
    private const string SarifVersion = "2.1.0";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    /// <inheritdoc />
    public string Format => "SARIF";

    /// <inheritdoc />
    public string FileExtension => ".sarif";

    /// <inheritdoc />
    public string Generate(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var rules = BuildRuleDescriptors(result);
        var results = BuildResults(result, rules);

        var sarif = new SarifLog
        {
            Schema = SarifSchemaUri,
            Version = SarifVersion,
            Runs =
            [
                new SarifRun
                {
                    Tool = new SarifTool
                    {
                        Driver = new SarifDriver
                        {
                            Name = "Signal Sentinel Scanner",
                            Version = result.ScannerVersion,
                            SemanticVersion = result.ScannerVersion,
                            InformationUri = "https://github.com/SignalCoding/signal-sentinel-scanner",
                            Organization = "Signal Coding Limited",
                            Rules = rules
                        }
                    },
                    Results = results,
                    Properties = new Dictionary<string, object?>
                    {
                        ["securityGrade"] = result.Grade.ToString(),
                        ["securityScore"] = result.Score,
                        ["scanTimestamp"] = result.ScanTimestamp.ToString("o"),
                        ["totalServers"] = result.Statistics.TotalServers,
                        ["totalSkills"] = result.Statistics.TotalSkills,
                        ["rubricVersion"] = result.RubricVersion,
                        ["environment"] = result.Environment,
                        ["scope"] = result.Scope
                    }
                }
            ]
        };

        return JsonSerializer.Serialize(sarif, JsonOptions);
    }

    private static List<SarifRule> BuildRuleDescriptors(ScanResult result)
    {
        var rules = new Dictionary<string, SarifRule>(StringComparer.Ordinal);

        foreach (var finding in result.Findings)
        {
            if (rules.ContainsKey(finding.RuleId))
            {
                continue;
            }

            var tags = new List<string> { finding.OwaspCode };
            tags.AddRange(finding.AstCodes);
            if (!string.IsNullOrEmpty(finding.McpCode))
            {
                tags.Add(finding.McpCode);
            }
            if (finding.Source == FindingSource.Skill)
            {
                tags.Add("agent-skill");
            }
            else
            {
                tags.Add("mcp");
            }

            rules[finding.RuleId] = new SarifRule
            {
                Id = finding.RuleId,
                Name = finding.Title,
                ShortDescription = new SarifMessage { Text = finding.Title },
                FullDescription = new SarifMessage { Text = finding.Description },
                Help = new SarifMessage { Text = finding.Remediation },
                DefaultConfiguration = new SarifConfiguration
                {
                    Level = MapSeverityToLevel(finding.Severity)
                },
                Properties = new Dictionary<string, object?>
                {
                    ["tags"] = tags,
                    ["precision"] = MapConfidenceToPrecision(finding.Confidence)
                }
            };
        }

        return [.. rules.Values];
    }

    private static List<SarifResult> BuildResults(ScanResult result, List<SarifRule> rules)
    {
        var ruleIndex = rules.Select((r, i) => (r.Id, i)).ToDictionary(x => x.Id, x => x.i, StringComparer.Ordinal);
        var results = new List<SarifResult>(result.Findings.Count);

        foreach (var finding in result.Findings)
        {
            var uri = finding.SkillFilePath ?? $"mcp-server://{finding.ServerName}";
            var logical = string.IsNullOrEmpty(finding.ToolName)
                ? finding.ServerName
                : $"{finding.ServerName}::{finding.ToolName}";

            var sarifResult = new SarifResult
            {
                RuleId = finding.RuleId,
                RuleIndex = ruleIndex.TryGetValue(finding.RuleId, out var idx) ? idx : null,
                Level = MapSeverityToLevel(finding.Severity),
                Message = new SarifMessage
                {
                    Text = BuildMessageText(finding)
                },
                Locations =
                [
                    new SarifLocation
                    {
                        PhysicalLocation = new SarifPhysicalLocation
                        {
                            ArtifactLocation = new SarifArtifactLocation { Uri = uri }
                        },
                        LogicalLocations =
                        [
                            new SarifLogicalLocation
                            {
                                FullyQualifiedName = logical,
                                Kind = finding.Source == FindingSource.Skill ? "skill" : "tool"
                            }
                        ]
                    }
                ],
                Properties = new Dictionary<string, object?>
                {
                    ["severity"] = finding.Severity.ToString(),
                    ["confidence"] = finding.Confidence,
                    ["occurrenceCount"] = finding.OccurrenceCount,
                    ["evidence"] = finding.Evidence,
                    ["astCodes"] = finding.AstCodes
                }
            };

            results.Add(sarifResult);
        }

        return results;
    }

    private static string BuildMessageText(Finding finding)
    {
        var suffix = finding.OccurrenceCount > 1 ? $" (x{finding.OccurrenceCount})" : string.Empty;
        return $"{finding.Title}: {finding.Description}{suffix}";
    }

    private static string MapSeverityToLevel(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium => "warning",
        Severity.Low or Severity.Info => "note",
        _ => "none"
    };

    private static string MapConfidenceToPrecision(double? confidence) => confidence switch
    {
        null => "medium",
        >= 0.9 => "very-high",
        >= 0.75 => "high",
        >= 0.5 => "medium",
        _ => "low"
    };

    // ---- SARIF model (minimal subset of v2.1.0) ----

    private sealed record SarifLog
    {
        [System.Text.Json.Serialization.JsonPropertyName("$schema")]
        public required string Schema { get; init; }

        public required string Version { get; init; }

        public required IReadOnlyList<SarifRun> Runs { get; init; }
    }

    private sealed record SarifRun
    {
        public required SarifTool Tool { get; init; }

        public IReadOnlyList<SarifResult>? Results { get; init; }

        public IReadOnlyDictionary<string, object?>? Properties { get; init; }
    }

    private sealed record SarifTool
    {
        public required SarifDriver Driver { get; init; }
    }

    private sealed record SarifDriver
    {
        public required string Name { get; init; }

        public string? Version { get; init; }

        public string? SemanticVersion { get; init; }

        public string? InformationUri { get; init; }

        public string? Organization { get; init; }

        public IReadOnlyList<SarifRule>? Rules { get; init; }
    }

    private sealed record SarifRule
    {
        public required string Id { get; init; }

        public string? Name { get; init; }

        public SarifMessage? ShortDescription { get; init; }

        public SarifMessage? FullDescription { get; init; }

        public SarifMessage? Help { get; init; }

        public SarifConfiguration? DefaultConfiguration { get; init; }

        public IReadOnlyDictionary<string, object?>? Properties { get; init; }
    }

    private sealed record SarifConfiguration
    {
        public required string Level { get; init; }
    }

    private sealed record SarifMessage
    {
        public required string Text { get; init; }
    }

    private sealed record SarifResult
    {
        public required string RuleId { get; init; }

        public int? RuleIndex { get; init; }

        public required string Level { get; init; }

        public required SarifMessage Message { get; init; }

        public IReadOnlyList<SarifLocation>? Locations { get; init; }

        public IReadOnlyDictionary<string, object?>? Properties { get; init; }
    }

    private sealed record SarifLocation
    {
        public SarifPhysicalLocation? PhysicalLocation { get; init; }

        public IReadOnlyList<SarifLogicalLocation>? LogicalLocations { get; init; }
    }

    private sealed record SarifPhysicalLocation
    {
        public SarifArtifactLocation? ArtifactLocation { get; init; }
    }

    private sealed record SarifArtifactLocation
    {
        public required string Uri { get; init; }
    }

    private sealed record SarifLogicalLocation
    {
        public required string FullyQualifiedName { get; init; }

        public string? Kind { get; init; }
    }
}
