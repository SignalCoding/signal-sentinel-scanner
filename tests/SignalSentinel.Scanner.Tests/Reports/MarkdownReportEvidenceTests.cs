// -----------------------------------------------------------------------
// <copyright file="MarkdownReportEvidenceTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// v3.0.1 round 2 (T5, security finding F-2): the markdown report renders evidence
// inside a single-backtick code span ("**Evidence:** `...`", MarkdownReportGenerator
// ~line 327) but SanitizeMarkdown neutralises only | [ ] < >. Evidence that carries
// a raw newline breaks out of the code span, and a backtick inside the evidence
// terminates it early - so hostile scanned content can inject markdown into a
// governance artefact. Evidence is attacker-influenced by definition: it is a slice
// of the scanned skill.
//
// Helper shape mirrors Reports/SarifReportGeneratorTests (no MarkdownReportGenerator
// test class existed to reuse).

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Reports;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Reports;

public class MarkdownReportEvidenceTests
{
    private const string EvidenceMarker = "**Evidence:**";

    /// <summary>Backtick, then a raw newline, then more content.</summary>
    private const string HostileEvidence = "alpha`beta\ngamma";

    private readonly MarkdownReportGenerator _generator = new();

    private static ScanResult MakeResult(params Finding[] findings) =>
        new()
        {
            ScanTimestamp = DateTimeOffset.UtcNow,
            ScannerVersion = "3.0.1",
            Servers = [],
            Findings = findings,
            AttackPaths = [],
            Grade = SecurityGrade.A,
            Score = 100,
            Statistics = new ScanStatistics()
        };

    private static Finding MakeFinding(string? evidence) =>
        new()
        {
            RuleId = "SS-016",
            OwaspCode = "ASI05",
            Severity = Severity.Medium,
            Title = "Skill Script Payload: Process Execution",
            Description = "Test description",
            Remediation = "Fix it",
            ServerName = "sample-skill",
            ToolName = "scripts/convert.py",
            Evidence = evidence,
            Source = FindingSource.Skill
        };

    private static string EvidenceLine(string report)
    {
        var lines = report.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        return lines.Single(l => l.StartsWith(EvidenceMarker, StringComparison.Ordinal));
    }

    [Fact]
    public void Generate_EvidenceWithRawNewline_RendersOnASingleLine()
    {
        var report = _generator.Generate(MakeResult(MakeFinding(HostileEvidence)));

        // A raw newline from the evidence would split the code span across lines.
        report.Replace("\r\n", "\n", StringComparison.Ordinal)
              .ShouldNotContain("beta\ngamma");

        var line = EvidenceLine(report);
        line.ShouldContain("alpha");
        line.ShouldContain("gamma");
    }

    [Fact]
    public void Generate_EvidenceWithBacktick_CannotTerminateTheCodeSpan()
    {
        var report = _generator.Generate(MakeResult(MakeFinding(HostileEvidence)));

        var line = EvidenceLine(report);
        var body = line[EvidenceMarker.Length..].Trim();

        // Tolerate either delimiter style (single or double backticks).
        var inner = body.Trim('`');

        // Tolerate backslash escaping; anything else (removal, HTML entity) also passes.
        inner.Replace("\\`", string.Empty, StringComparison.Ordinal)
             .ShouldNotContain("`", Case.Sensitive,
                 "An unescaped backtick in evidence terminates the code span and lets " +
                 "scanned content inject markdown into the report. Rendered line: " + line);
    }

    [Fact]
    public void Generate_OrdinaryEvidence_StillRendersInACodeSpan()
    {
        var report = _generator.Generate(MakeResult(MakeFinding("subprocess.run([\"soffice\"])")));

        var line = EvidenceLine(report);
        line.ShouldContain("subprocess.run");
        line.ShouldContain("`");
    }

    [Fact]
    public void Generate_NoEvidence_RendersNoEvidenceLine()
    {
        var report = _generator.Generate(MakeResult(MakeFinding(null)));

        report.ShouldNotContain(EvidenceMarker);
    }
}
