using System.Text;
using System.Web;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Scoring;

namespace SignalSentinel.Scanner.Reports;

/// <summary>
/// Generates HTML format scan reports with Signal Coding branding.
/// Security hardened with XSS protection.
/// </summary>
public sealed class HtmlReportGenerator : IReportGenerator
{
    public string Format => "HTML";
    public string FileExtension => ".html";

    // Security: Maximum lengths for display
    private const int MaxTitleLength = 200;
    private const int MaxDescriptionLength = 5000;
    private const int MaxEvidenceLength = 500;

    public string Generate(ScanResult result)
    {
        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        // Security: CSP header to prevent XSS
        sb.AppendLine("  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; script-src 'none';\">");
        sb.AppendLine("  <title>Signal Sentinel Security Report</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine(GetStyles());
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        // Header
        sb.AppendLine("  <header>");
        sb.AppendLine("    <div class=\"header-content\">");
        sb.AppendLine("      <h1>&#128737; Signal Sentinel</h1>");
        sb.AppendLine("      <p class=\"subtitle\">MCP Security Scan Report</p>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </header>");

        sb.AppendLine("  <main>");

        // Grade Card
        var gradeColor = SeverityScorer.GetGradeColor(result.Grade);
        sb.AppendLine("    <section class=\"grade-section\">");
        sb.AppendLine($"      <div class=\"grade-card\" style=\"border-color: {Encode(gradeColor)}\">");
        sb.AppendLine($"        <div class=\"grade\" style=\"color: {Encode(gradeColor)}\">{Encode(result.Grade.ToString())}</div>");
        sb.AppendLine($"        <div class=\"score\">{result.Score}/100</div>");
        sb.AppendLine($"        <div class=\"grade-desc\">{Encode(SeverityScorer.GetGradeDescription(result.Grade))}</div>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <div class=\"scan-meta\">");
        sb.AppendLine($"        <p><strong>Scan Date:</strong> {Encode(result.ScanTimestamp.ToString("yyyy-MM-dd HH:mm:ss"))} UTC</p>");
        sb.AppendLine($"        <p><strong>Scanner Version:</strong> {Encode(result.ScannerVersion)}</p>");
        sb.AppendLine($"        <p><strong>Duration:</strong> {result.Statistics.ScanDurationMs}ms</p>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </section>");

        // Statistics
        sb.AppendLine("    <section>");
        sb.AppendLine("      <h2>Summary Statistics</h2>");
        sb.AppendLine("      <div class=\"stats-grid\">");
        sb.AppendLine(StatCard("Servers", result.Statistics.ServersConnected.ToString(), result.Statistics.TotalServers.ToString(), "#3b82f6"));
        sb.AppendLine(StatCard("Tools", result.Statistics.TotalTools.ToString(), null, "#8b5cf6"));
        sb.AppendLine(StatCard("Critical", result.Statistics.CriticalFindings.ToString(), null, "#ef4444"));
        sb.AppendLine(StatCard("High", result.Statistics.HighFindings.ToString(), null, "#f97316"));
        sb.AppendLine(StatCard("Medium", result.Statistics.MediumFindings.ToString(), null, "#eab308"));
        sb.AppendLine(StatCard("Low", result.Statistics.LowFindings.ToString(), null, "#22c55e"));
        sb.AppendLine(StatCard("Attack Paths", result.Statistics.AttackPathCount.ToString(), null, "#dc2626"));
        sb.AppendLine("      </div>");
        sb.AppendLine("    </section>");

        // OWASP Compliance
        var owaspGroups = OwaspMapper.GroupByOwaspCode(result.Findings);
        var matrix = OwaspMapper.GenerateComplianceMatrix(owaspGroups);
        var coverageScore = OwaspMapper.CalculateCoverageScore(owaspGroups);

        sb.AppendLine("    <section>");
        sb.AppendLine("      <h2>OWASP Agentic AI Top 10 Compliance</h2>");
        sb.AppendLine($"      <p class=\"coverage\">Coverage Score: <strong>{coverageScore:F0}%</strong></p>");
        sb.AppendLine("      <table class=\"compliance-table\">");
        sb.AppendLine("        <thead><tr><th>Code</th><th>Risk Category</th><th>Status</th><th>Findings</th></tr></thead>");
        sb.AppendLine("        <tbody>");
        foreach (var row in matrix)
        {
            var (statusClass, statusText) = row.Status switch
            {
                ComplianceStatus.FullyCompliant => ("status-pass", "&#10004; Pass"),
                ComplianceStatus.Compliant => ("status-pass", "&#10004; Pass"),
                ComplianceStatus.NeedsImprovement => ("status-warn", "&#9888; Needs Improvement"),
                ComplianceStatus.PartiallyCompliant => ("status-partial", "&#9679; Partial"),
                ComplianceStatus.NonCompliant => ("status-fail", "&#10060; Fail"),
                _ => ("", "Unknown")
            };
            var truncatedDesc = TruncateAndEncode(row.Description, 60);
            sb.AppendLine($"          <tr><td><code>{Encode(row.Code)}</code></td><td>{truncatedDesc}</td><td class=\"{statusClass}\">{statusText}</td><td>{row.FindingsCount}</td></tr>");
        }
        sb.AppendLine("        </tbody>");
        sb.AppendLine("      </table>");
        sb.AppendLine("    </section>");

        // Attack Paths
        if (result.AttackPaths.Count > 0)
        {
            sb.AppendLine("    <section class=\"attack-paths\">");
            sb.AppendLine("      <h2>&#9888; Attack Paths Detected</h2>");
            foreach (var path in result.AttackPaths)
            {
                var color = SeverityScorer.GetSeverityColor(path.Severity);
                sb.AppendLine($"      <div class=\"attack-path\" style=\"border-left-color: {Encode(color)}\">");
                sb.AppendLine($"        <h3>{Encode(path.Id)}: {Encode(path.Severity.ToString())}</h3>");
                sb.AppendLine($"        <p>{TruncateAndEncode(path.Description, MaxDescriptionLength)}</p>");
                sb.AppendLine("        <div class=\"chain\">");
                foreach (var step in path.Steps)
                {
                    sb.AppendLine($"          <span class=\"step\">{Encode(step.ServerName)}:{Encode(step.ToolName)}</span>");
                }
                sb.AppendLine("        </div>");
                sb.AppendLine($"        <p class=\"remediation\"><strong>Remediation:</strong> {TruncateAndEncode(path.Remediation, MaxDescriptionLength)}</p>");
                sb.AppendLine("      </div>");
            }
            sb.AppendLine("    </section>");
        }

        // Findings
        sb.AppendLine("    <section>");
        sb.AppendLine("      <h2>Detailed Findings</h2>");
        foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info })
        {
            var severityFindings = result.Findings.Where(f => f.Severity == severity).ToList();
            if (severityFindings.Count == 0) continue;

            var color = SeverityScorer.GetSeverityColor(severity);
            sb.AppendLine($"      <h3 style=\"color: {Encode(color)}\">{Encode(severity.ToString())} ({severityFindings.Count})</h3>");

            foreach (var finding in severityFindings)
            {
                sb.AppendLine($"      <div class=\"finding\" style=\"border-left-color: {Encode(color)}\">");
                sb.AppendLine($"        <h4>[{Encode(finding.RuleId)}] {TruncateAndEncode(finding.Title, MaxTitleLength)}</h4>");
                sb.AppendLine($"        <p><strong>Server:</strong> {Encode(finding.ServerName)}");
                if (finding.ToolName is not null)
                {
                    sb.AppendLine($" | <strong>Tool:</strong> {Encode(finding.ToolName)}");
                }
                sb.AppendLine($" | <strong>OWASP:</strong> {Encode(finding.OwaspCode)}</p>");
                sb.AppendLine($"        <p>{TruncateAndEncode(finding.Description, MaxDescriptionLength)}</p>");
                sb.AppendLine($"        <p class=\"remediation\"><strong>Remediation:</strong> {TruncateAndEncode(finding.Remediation, MaxDescriptionLength)}</p>");
                if (finding.Evidence is not null)
                {
                    sb.AppendLine($"        <p class=\"evidence\"><strong>Evidence:</strong> <code>{TruncateAndEncode(finding.Evidence, MaxEvidenceLength)}</code></p>");
                }
                sb.AppendLine("      </div>");
            }
        }
        sb.AppendLine("    </section>");

        sb.AppendLine("  </main>");

        // Footer
        sb.AppendLine("  <footer>");
        sb.AppendLine("    <p>Report generated by Signal Sentinel Scanner</p>");
        sb.AppendLine("    <p>&#169; 2026 Signal Coding Limited. All rights reserved.</p>");
        sb.AppendLine("  </footer>");

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    /// <summary>
    /// HTML encodes a string to prevent XSS.
    /// </summary>
    private static string Encode(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        return HttpUtility.HtmlEncode(text);
    }

    /// <summary>
    /// Truncates and HTML encodes a string.
    /// </summary>
    private static string TruncateAndEncode(string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        if (text.Length > maxLength)
        {
            text = text[..maxLength] + "...";
        }

        return Encode(text);
    }

    private static string StatCard(string label, string value, string? subtitle, string color)
    {
        var sub = subtitle is not null ? $"<span class=\"stat-sub\">/ {Encode(subtitle)}</span>" : "";
        return $@"        <div class=""stat-card"" style=""border-top-color: {Encode(color)}"">
          <div class=""stat-value"" style=""color: {Encode(color)}"">{Encode(value)}{sub}</div>
          <div class=""stat-label"">{Encode(label)}</div>
        </div>";
    }

    private static string GetStyles() => """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1f2937; background: #f3f4f6; }
        header { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 2rem; }
        .header-content h1 { font-size: 2rem; margin-bottom: 0.25rem; }
        .subtitle { opacity: 0.9; font-size: 1.1rem; }
        main { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        section { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        h2 { color: #1e3a8a; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid #e5e7eb; }
        h3 { margin: 1rem 0 0.5rem; }
        .grade-section { display: flex; gap: 2rem; align-items: center; flex-wrap: wrap; }
        .grade-card { text-align: center; padding: 1.5rem 2rem; border: 4px solid; border-radius: 12px; }
        .grade { font-size: 4rem; font-weight: bold; }
        .score { font-size: 1.5rem; color: #6b7280; }
        .grade-desc { max-width: 300px; margin-top: 0.5rem; font-size: 0.9rem; color: #4b5563; }
        .scan-meta { color: #6b7280; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; }
        .stat-card { background: #f9fafb; padding: 1rem; border-radius: 8px; text-align: center; border-top: 4px solid; }
        .stat-value { font-size: 2rem; font-weight: bold; }
        .stat-sub { font-size: 1rem; color: #9ca3af; }
        .stat-label { color: #6b7280; font-size: 0.875rem; }
        .compliance-table { width: 100%; border-collapse: collapse; }
        .compliance-table th, .compliance-table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #e5e7eb; }
        .compliance-table th { background: #f9fafb; font-weight: 600; }
        .status-pass { color: #22c55e; }
        .status-warn { color: #eab308; }
        .status-partial { color: #f97316; }
        .status-fail { color: #ef4444; }
        .coverage { font-size: 1.1rem; margin-bottom: 1rem; }
        .finding, .attack-path { border-left: 4px solid; padding: 1rem; margin-bottom: 1rem; background: #f9fafb; border-radius: 0 8px 8px 0; }
        .finding h4, .attack-path h3 { margin-bottom: 0.5rem; }
        .remediation { color: #1e40af; margin-top: 0.5rem; }
        .evidence { background: #fef3c7; padding: 0.5rem; border-radius: 4px; margin-top: 0.5rem; word-break: break-all; }
        .evidence code { background: transparent; }
        .chain { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.5rem 0; }
        .step { background: #fee2e2; padding: 0.25rem 0.75rem; border-radius: 4px; font-family: monospace; }
        code { background: #f3f4f6; padding: 0.125rem 0.375rem; border-radius: 4px; font-size: 0.875rem; word-break: break-all; }
        footer { text-align: center; padding: 2rem; color: #6b7280; font-size: 0.875rem; }
        @media (max-width: 640px) { .grade-section { flex-direction: column; text-align: center; } }
        """;
}
