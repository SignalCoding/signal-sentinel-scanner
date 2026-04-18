using System.Text;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Scoring;

namespace SignalSentinel.Scanner.Reports;

/// <summary>
/// Generates Markdown format scan reports.
/// </summary>
public sealed class MarkdownReportGenerator : IReportGenerator
{
    public string Format => "Markdown";
    public string FileExtension => ".md";

    private static string SanitizeMarkdown(string? value, int maxLength = 500)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var sanitized = value.Length > maxLength ? value[..(maxLength - 3)] + "..." : value;
        return sanitized
            .Replace("|", "\\|")
            .Replace("[", "\\[")
            .Replace("]", "\\]")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;");
    }

    public string Generate(ScanResult result)
    {
        var sb = new StringBuilder();

        // Header
        sb.AppendLine("# Signal Sentinel Security Scan Report");
        sb.AppendLine();
        sb.AppendLine($"**Scan Date:** {result.ScanTimestamp:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"**Scanner Version:** {result.ScannerVersion} (rubric v{result.RubricVersion})");
        sb.AppendLine($"**Environment:** {SanitizeMarkdown(result.Environment)}");
        sb.AppendLine();

        // v2.3.0 scope disclosure - tells users what was and was not scanned.
        if (result.Scope is not null)
        {
            sb.AppendLine("## Scanner Scope");
            sb.AppendLine();
            sb.AppendLine("> **Signal Sentinel is a first-pass authoring aid, not an audit tool.** ");
            sb.AppendLine("> The items below declare exactly what was analysed. Complement with the");
            sb.AppendLine("> listed third-party tools for defence in depth.");
            sb.AppendLine();
            if (result.Scope.Scanned.Count > 0)
            {
                sb.AppendLine("**Scanned:**");
                foreach (var item in result.Scope.Scanned) sb.AppendLine($"- {SanitizeMarkdown(item)}");
                sb.AppendLine();
            }
            if (result.Scope.NotScanned.Count > 0)
            {
                sb.AppendLine("**Not scanned:**");
                foreach (var item in result.Scope.NotScanned) sb.AppendLine($"- {SanitizeMarkdown(item)}");
                sb.AppendLine();
            }
            if (result.Scope.ComplementaryTools.Count > 0)
            {
                sb.AppendLine("**Complement with:** " + string.Join(", ", result.Scope.ComplementaryTools.Select(t => SanitizeMarkdown(t))));
                sb.AppendLine();
            }
        }

        // Grade Summary
        sb.AppendLine("## Security Grade");
        sb.AppendLine();
        sb.AppendLine($"### Grade: {result.Grade} ({result.Score}/100)");
        sb.AppendLine();
        sb.AppendLine(SeverityScorer.GetGradeDescription(result.Grade));
        sb.AppendLine();

        // Statistics
        sb.AppendLine("## Summary Statistics");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("|--------|-------|");
        sb.AppendLine($"| Servers Scanned | {result.Statistics.TotalServers} |");
        sb.AppendLine($"| Servers Connected | {result.Statistics.ServersConnected} |");
        sb.AppendLine($"| Total Tools | {result.Statistics.TotalTools} |");
        sb.AppendLine($"| Total Resources | {result.Statistics.TotalResources} |");
        sb.AppendLine($"| Total Prompts | {result.Statistics.TotalPrompts} |");
        sb.AppendLine($"| Critical Findings | {result.Statistics.CriticalFindings} |");
        sb.AppendLine($"| High Findings | {result.Statistics.HighFindings} |");
        sb.AppendLine($"| Medium Findings | {result.Statistics.MediumFindings} |");
        sb.AppendLine($"| Low Findings | {result.Statistics.LowFindings} |");
        sb.AppendLine($"| Info Findings | {result.Statistics.InfoFindings} |");
        sb.AppendLine($"| Attack Paths | {result.Statistics.AttackPathCount} |");
        if (result.Statistics.TotalSkills > 0)
        {
            sb.AppendLine($"| Skills Scanned | {result.Statistics.TotalSkills} |");
            sb.AppendLine($"| Scripts Analysed | {result.Statistics.TotalScripts} |");
        }
        sb.AppendLine($"| Scan Duration | {result.Statistics.ScanDurationMs}ms |");
        sb.AppendLine();

        // Servers
        sb.AppendLine("## Scanned Servers");
        sb.AppendLine();
        foreach (var server in result.Servers)
        {
            var status = server.ConnectionSuccessful ? "✅ Connected" : "❌ Failed";
            sb.AppendLine($"### {SanitizeMarkdown(server.Name)}");
            sb.AppendLine();
            sb.AppendLine($"- **Status:** {status}");
            sb.AppendLine($"- **Transport:** {SanitizeMarkdown(server.Transport)}");
            if (server.Version is not null)
            {
                sb.AppendLine($"- **Version:** {SanitizeMarkdown(server.Version)}");
            }
            if (server.SourceConfig is not null)
            {
                sb.AppendLine($"- **Config:** `{SanitizeMarkdown(server.SourceConfig)}`");
            }
            sb.AppendLine($"- **Tools:** {server.ToolCount}");
            sb.AppendLine($"- **Resources:** {server.ResourceCount}");
            sb.AppendLine($"- **Prompts:** {server.PromptCount}");
            if (server.ConnectionError is not null)
            {
                sb.AppendLine($"- **Error:** {SanitizeMarkdown(server.ConnectionError)}");
            }
            sb.AppendLine();
        }

        // Skills
        if (result.Skills.Count > 0)
        {
            sb.AppendLine("## Scanned Skills");
            sb.AppendLine();
            sb.AppendLine("| Skill | Platform | Scripts | Level |");
            sb.AppendLine("|-------|----------|---------|-------|");
            foreach (var skill in result.Skills)
            {
                var level = skill.IsProjectLevel ? "Project" : "Personal";
                sb.AppendLine($"| {SanitizeMarkdown(skill.Name)} | {SanitizeMarkdown(skill.Platform ?? "Unknown")} | {skill.ScriptCount} | {level} |");
            }
            sb.AppendLine();
        }

        // OWASP Compliance Matrix
        var owaspGroups = OwaspMapper.GroupByOwaspCode(result.Findings);
        var matrix = OwaspMapper.GenerateComplianceMatrix(owaspGroups);
        var coverageScore = OwaspMapper.CalculateCoverageScore(owaspGroups);

        sb.AppendLine("## OWASP Agentic AI Top 10 Compliance");
        sb.AppendLine();
        sb.AppendLine($"**Coverage Score:** {coverageScore:F0}%");
        sb.AppendLine();
        sb.AppendLine("| Code | Risk Category | Status | Findings |");
        sb.AppendLine("|------|--------------|--------|----------|");
        foreach (var row in matrix)
        {
            var statusEmoji = row.Status switch
            {
                ComplianceStatus.FullyCompliant => "✅",
                ComplianceStatus.Compliant => "✅",
                ComplianceStatus.NeedsImprovement => "⚠️",
                ComplianceStatus.PartiallyCompliant => "🟡",
                ComplianceStatus.NonCompliant => "❌",
                _ => "❓"
            };
            sb.AppendLine($"| {row.Code} | {row.Description[..Math.Min(50, row.Description.Length)]} | {statusEmoji} | {row.FindingsCount} |");
        }
        sb.AppendLine();

        // OWASP MCP Top 10 Compliance (dual mapping)
        var mcpFindings = result.Findings.Where(f => f.Source == FindingSource.Mcp).ToList();
        if (mcpFindings.Count > 0)
        {
            var mcpGroups = OwaspMapper.GroupByMcpCode(mcpFindings);
            var mcpMatrix = OwaspMapper.GenerateComplianceMatrix(mcpGroups);

            sb.AppendLine("## OWASP MCP Top 10 Compliance");
            sb.AppendLine();
            sb.AppendLine("| Code | Risk Category | Status | Findings |");
            sb.AppendLine("|------|--------------|--------|----------|");
            foreach (var row in mcpMatrix)
            {
                var statusEmoji = row.Status switch
                {
                    ComplianceStatus.FullyCompliant => "✅",
                    ComplianceStatus.Compliant => "✅",
                    ComplianceStatus.NeedsImprovement => "⚠️",
                    ComplianceStatus.PartiallyCompliant => "🟡",
                    ComplianceStatus.NonCompliant => "❌",
                    _ => "❓"
                };
                sb.AppendLine($"| {row.Code} | {row.Description[..Math.Min(50, row.Description.Length)]} | {statusEmoji} | {row.FindingsCount} |");
            }
            sb.AppendLine();
        }

        // Attack Paths
        if (result.AttackPaths.Count > 0)
        {
            sb.AppendLine("## Attack Paths Detected");
            sb.AppendLine();
            sb.AppendLine("⚠️ **Warning:** The following cross-server attack chains were identified:");
            sb.AppendLine();

            foreach (var path in result.AttackPaths)
            {
                var severityEmoji = path.Severity switch
                {
                    Severity.Critical => "🔴",
                    Severity.High => "🟠",
                    _ => "🟡"
                };

                sb.AppendLine($"### {severityEmoji} {path.Id}: {path.Severity}");
                sb.AppendLine();
                sb.AppendLine(SanitizeMarkdown(path.Description));
                sb.AppendLine();
                sb.AppendLine("**Attack Chain:**");
                sb.AppendLine();
                for (var i = 0; i < path.Steps.Count; i++)
                {
                    var step = path.Steps[i];
                    var arrow = i < path.Steps.Count - 1 ? " →" : "";
                    sb.AppendLine($"{i + 1}. `{SanitizeMarkdown(step.ServerName)}:{SanitizeMarkdown(step.ToolName)}` ({step.Capability}){arrow}");
                }
                sb.AppendLine();
                sb.AppendLine($"**Remediation:** {SanitizeMarkdown(path.Remediation)}");
                sb.AppendLine();
            }
        }

        // Findings by Severity
        sb.AppendLine("## Findings");
        sb.AppendLine();

        foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info })
        {
            var severityFindings = result.Findings.Where(f => f.Severity == severity).ToList();
            if (severityFindings.Count == 0)
            {
                continue;
            }

            var emoji = severity switch
            {
                Severity.Critical => "🔴",
                Severity.High => "🟠",
                Severity.Medium => "🟡",
                Severity.Low => "🟢",
                Severity.Info => "🔵",
                _ => "⚪"
            };

            sb.AppendLine($"### {emoji} {severity} Findings ({severityFindings.Count})");
            sb.AppendLine();

            foreach (var finding in severityFindings)
            {
                var occurrence = finding.OccurrenceCount > 1 ? $" [x{finding.OccurrenceCount}]" : string.Empty;
                sb.AppendLine($"#### [{finding.RuleId}] {SanitizeMarkdown(finding.Title)}{occurrence}");
                sb.AppendLine();
                var sourceLabel = finding.Source == FindingSource.Skill ? "Skill" : "Server";
                sb.AppendLine($"- **{sourceLabel}:** {SanitizeMarkdown(finding.ServerName)}");
                if (finding.ToolName is not null)
                {
                    sb.AppendLine($"- **Tool:** {SanitizeMarkdown(finding.ToolName)}");
                }
                sb.AppendLine($"- **OWASP ASI:** {finding.OwaspCode}");
                if (finding.AstCodes.Count > 0)
                {
                    sb.AppendLine($"- **OWASP AST:** {string.Join(", ", finding.AstCodes)}");
                }
                if (finding.McpCode is not null)
                {
                    sb.AppendLine($"- **MCP Code:** {finding.McpCode}");
                }
                if (finding.Confidence.HasValue)
                {
                    var conf = finding.Confidence.Value;
                    var label = conf switch
                    {
                        >= 0.9 => "high",
                        >= 0.7 => "medium",
                        >= 0.5 => "candidate",
                        _ => "weak"
                    };
                    sb.AppendLine($"- **Confidence:** {conf:P0} ({label})");
                }
                sb.AppendLine();
                sb.AppendLine($"**Description:** {SanitizeMarkdown(finding.Description)}");
                sb.AppendLine();
                sb.AppendLine($"**Remediation:** {SanitizeMarkdown(finding.Remediation)}");
                if (finding.Evidence is not null)
                {
                    sb.AppendLine();
                    sb.AppendLine($"**Evidence:** `{SanitizeMarkdown(finding.Evidence)}`");
                }
                sb.AppendLine();
            }
        }

        // v2.3.0 Accepted Risks section - suppressed findings retained for audit.
        if (result.SuppressedFindings.Count > 0)
        {
            sb.AppendLine("## Accepted Risks");
            sb.AppendLine();
            sb.AppendLine("The following findings have been explicitly accepted via `.sentinel-suppressions.json`.");
            sb.AppendLine("They are retained here for audit trail purposes and do not contribute to the active grade.");
            sb.AppendLine();
            if (result.GradeWithoutSuppressions is not null && result.ScoreWithoutSuppressions is not null)
            {
                sb.AppendLine($"> **Technical-debt exposure:** if these {result.SuppressedFindings.Count} suppression(s) were removed, your grade would be **{result.GradeWithoutSuppressions} ({result.ScoreWithoutSuppressions}/100)** instead of {result.Grade} ({result.Score}/100).");
                sb.AppendLine();
            }
            sb.AppendLine("| Rule | Severity | Target | Justification | Approved By | Expires |");
            sb.AppendLine("|------|----------|--------|---------------|-------------|---------|");
            foreach (var f in result.SuppressedFindings)
            {
                var target = string.IsNullOrEmpty(f.ToolName)
                    ? SanitizeMarkdown(f.ServerName)
                    : $"{SanitizeMarkdown(f.ServerName)}:{SanitizeMarkdown(f.ToolName)}";
                var expires = f.Suppression?.ExpiresOn?.ToString("yyyy-MM-dd") ?? "-";
                sb.AppendLine($"| {f.RuleId} | {f.Severity} | {target} | {SanitizeMarkdown(f.Suppression?.Justification ?? "")} | {SanitizeMarkdown(f.Suppression?.ApprovedBy ?? "-")} | {expires} |");
            }
            sb.AppendLine();
        }

        // Footer
        sb.AppendLine("---");
        sb.AppendLine();
        sb.AppendLine("*Report generated by [Signal Sentinel Scanner](https://github.com/SignalCoding/signal-sentinel-scanner)*");
        sb.AppendLine();
        sb.AppendLine("*Secure your MCP servers with [Signal Sentinel Gateway](https://signalcoding.co.uk/products/sentinel-scanner/)*");

        return sb.ToString();
    }
}
