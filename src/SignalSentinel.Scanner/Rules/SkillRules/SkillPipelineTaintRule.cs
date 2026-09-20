// -----------------------------------------------------------------------
// <copyright file="SkillPipelineTaintRule.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// SS-038: Detects fetch-to-exec taint flows in bundled skill scripts and in fenced code
/// blocks of the skill's instructions. Maps to OWASP ASI05 (Unexpected Code Execution).
/// </summary>
/// <remarks>
/// SS-016 (Skill Script Payload) already flags <c>curl ... | bash</c> as a single regex.
/// This rule generalises that to the pattern rather than the literal string: any network
/// fetch (curl, wget, Invoke-WebRequest, requests.get, fetch, ...) whose output reaches a
/// shell, an eval, or a language-native exec sink, either directly, through a base64
/// decode step, or through a variable assigned from the fetch and consumed within
/// <see cref="PipelineTaint.MaxVariableWindowLines"/> lines. A direct or encoded pipe is
/// Critical: there is no legitimate reason to run unreviewed network content as code. A
/// variable-mediated flow is High: still almost always malicious, but the extra
/// indirection leaves slightly more room for a false positive (e.g. the variable is
/// reused for something else by the time it reaches the sink).
/// </remarks>
public sealed class SkillPipelineTaintRule : IRule
{
    public string Id => RuleConstants.Rules.SkillPipelineTaint;
    public string Name => "Skill Script Pipeline Taint";
    public string OwaspCode => OwaspAsiCodes.ASI05;
    public string Description =>
        "Detects network-fetched content piped or assigned into a shell, eval, or exec sink in skill scripts and instructions.";
    public bool EnabledByDefault => true;
    public IReadOnlyList<string> AstCodes => [OwaspAstCodes.AST01, OwaspAstCodes.AST06];

    /// <summary>
    /// v3.0.0 (WP10): taint flows inside the document are evaluated per fenced/indented
    /// code block from the document segmenter (language hint included); prose cannot
    /// execute, and bundled scripts are scanned separately below.
    /// </summary>
    public SegmentKind ApplicableSegments => SegmentKind.FencedCode;

    public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();

        foreach (var skill in context.Skills)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var script in skill.Scripts)
            {
                foreach (var taint in PipelineTaint.Analyse(script.Content))
                {
                    findings.Add(Create(skill, taint, script.RelativePath));
                }
            }

            // v3.0.0 (WP10): segments replace fence-regex extraction, so indented
            // blocks and previously unlisted fence languages are covered too. The
            // location string keeps the pre-WP10 convention ("unspecified" when the
            // fence carries no info string).
            foreach (var block in SegmentFilter.SegmentsFor(skill, SegmentKind.FencedCode))
            {
                foreach (var taint in PipelineTaint.Analyse(block.Content))
                {
                    var language = block.Language ?? "unspecified";
                    findings.Add(Create(skill, taint, $"(fenced {language} code block)"));
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private Finding Create(SkillDefinition skill, TaintFinding taint, string location)
    {
        var inBlock = location.StartsWith("(fenced", StringComparison.Ordinal);
        var sourceLine = inBlock ? $"line {taint.SourceLine} of the block" : $"line {taint.SourceLine}";
        var sinkLine = inBlock ? $"line {taint.SinkLine} of the block" : $"line {taint.SinkLine}";

        var (severity, title, whatHappens) = taint switch
        {
            { Flow: TaintFlow.DirectPipe } => (
                Severity.Critical,
                "Script Pipeline Taint: Fetch Piped Directly To Execution",
                $"a network fetch on {sourceLine} ('{taint.SourceText}') is piped directly into an execution sink on {sinkLine} ('{taint.SinkText}'). This runs unreviewed remote content as code."),
            { Flow: TaintFlow.EncodedPipe, HasNetworkSource: true } => (
                Severity.Critical,
                "Script Pipeline Taint: Fetch Decoded And Executed",
                $"a network fetch on {sourceLine} ('{taint.SourceText}') is base64-decoded and piped into an execution sink on {sinkLine} ('{taint.SinkText}'). This runs unreviewed remote content as code."),
            { Flow: TaintFlow.EncodedPipe } => (
                Severity.Critical,
                "Script Pipeline Taint: Embedded Payload Decoded And Executed",
                $"an embedded payload is decoded on {sourceLine} ('{taint.SourceText}') and piped into an execution sink on {sinkLine} ('{taint.SinkText}'). The script carries its own hidden command."),
            _ => (
                Severity.High,
                "Script Pipeline Taint: Fetch Result Executed Via Variable",
                $"a network fetch on {sourceLine} ('{taint.SourceText}') is captured in '${taint.Variable}' and later reaches an execution sink on {sinkLine} ('{taint.SinkText}'). Fetched content should never be executed without review.")
        };

        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = severity,
            Title = title,
            Description = $"In '{location}' of skill '{skill.Name}', {whatHappens}",
            Remediation = "Never pipe or pass fetched content to a shell, eval, or exec sink. Download to a file, verify its checksum or signature, and inspect it before running.",
            ServerName = skill.Name,
            ToolName = location,
            Evidence = DescriptionScan.Truncate($"L{taint.SourceLine}: {taint.SourceText} => L{taint.SinkLine}: {taint.SinkText}"),
            Confidence = taint.Flow == TaintFlow.VariableMediated ? 0.75 : 0.95,
            Source = FindingSource.Skill,
            SkillFilePath = skill.FilePath
        };
    }
}
