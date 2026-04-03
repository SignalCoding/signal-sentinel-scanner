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

    public string Generate(ScanResult result)
    {
        var sb = new StringBuilder();

        // Header
        sb.AppendLine("# Signal Sentinel Security Scan Report");
        sb.AppendLine();
        sb.AppendLine($"**Scan Date:** {result.ScanTimestamp:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"**Scanner Version:** {result.ScannerVersion}");
        sb.AppendLine();

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
        sb.AppendLine($"| Scan Duration | {result.Statistics.ScanDurationMs}ms |");
        sb.AppendLine();

        // Servers
        sb.AppendLine("## Scanned Servers");
        sb.AppendLine();
        foreach (var server in result.Servers)
        {
            var status = server.ConnectionSuccessful ? "✅ Connected" : "❌ Failed";
            sb.AppendLine($"### {server.Name}");
            sb.AppendLine();
            sb.AppendLine($"- **Status:** {status}");
            sb.AppendLine($"- **Transport:** {server.Transport}");
            if (server.Version is not null)
            {
                sb.AppendLine($"- **Version:** {server.Version}");
            }
            if (server.SourceConfig is not null)
            {
                sb.AppendLine($"- **Config:** `{server.SourceConfig}`");
            }
            sb.AppendLine($"- **Tools:** {server.ToolCount}");
            sb.AppendLine($"- **Resources:** {server.ResourceCount}");
            sb.AppendLine($"- **Prompts:** {server.PromptCount}");
            if (server.ConnectionError is not null)
            {
                sb.AppendLine($"- **Error:** {server.ConnectionError}");
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
                sb.AppendLine(path.Description);
                sb.AppendLine();
                sb.AppendLine("**Attack Chain:**");
                sb.AppendLine();
                for (var i = 0; i < path.Steps.Count; i++)
                {
                    var step = path.Steps[i];
                    var arrow = i < path.Steps.Count - 1 ? " →" : "";
                    sb.AppendLine($"{i + 1}. `{step.ServerName}:{step.ToolName}` ({step.Capability}){arrow}");
                }
                sb.AppendLine();
                sb.AppendLine($"**Remediation:** {path.Remediation}");
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
                sb.AppendLine($"#### [{finding.RuleId}] {finding.Title}");
                sb.AppendLine();
                sb.AppendLine($"- **Server:** {finding.ServerName}");
                if (finding.ToolName is not null)
                {
                    sb.AppendLine($"- **Tool:** {finding.ToolName}");
                }
                sb.AppendLine($"- **OWASP:** {finding.OwaspCode}");
                if (finding.Confidence.HasValue)
                {
                    sb.AppendLine($"- **Confidence:** {finding.Confidence:P0}");
                }
                sb.AppendLine();
                sb.AppendLine($"**Description:** {finding.Description}");
                sb.AppendLine();
                sb.AppendLine($"**Remediation:** {finding.Remediation}");
                if (finding.Evidence is not null)
                {
                    sb.AppendLine();
                    sb.AppendLine($"**Evidence:** `{finding.Evidence}`");
                }
                sb.AppendLine();
            }
        }

        // Footer
        sb.AppendLine("---");
        sb.AppendLine();
        sb.AppendLine("*Report generated by [Signal Sentinel Scanner](https://github.com/signal-coding/signal-sentinel)*");
        sb.AppendLine();
        sb.AppendLine("*Secure your MCP servers with [Signal Sentinel Gateway](https://signalsentinel.co.uk)*");

        return sb.ToString();
    }
}
