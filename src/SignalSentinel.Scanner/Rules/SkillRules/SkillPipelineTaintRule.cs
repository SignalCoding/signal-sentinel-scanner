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

            foreach (var (language, taints) in PipelineTaint.AnalyseFencedCodeBlocks(skill.InstructionsBody))
            {
                foreach (var taint in taints)
                {
                    findings.Add(Create(skill, taint, $"(fenced {language} code block)"));
                }
            }
        }

        return Task.FromResult<IEnumerable<Finding>>(findings);
    }

    private Finding Create(SkillDefinition skill, TaintFinding taint, string location)
    {
        var (severity, flowLabel) = taint.Flow switch
        {
            TaintFlow.DirectPipe => (Severity.Critical, "is piped directly into"),
            TaintFlow.EncodedPipe => (Severity.Critical, "is base64-decoded and piped into"),
            TaintFlow.VariableMediated => (Severity.High, $"is captured in '${taint.Variable}' and later reaches"),
            _ => (Severity.High, "reaches")
        };

        var description = taint.Flow == TaintFlow.VariableMediated
            ? $"In '{location}' of skill '{skill.Name}', a network fetch on line {taint.SourceLine} ('{taint.SourceText}') {flowLabel} an execution sink on line {taint.SinkLine} ('{taint.SinkText}'). Fetched content should never be executed without review."
            : $"In '{location}' of skill '{skill.Name}', a network fetch on line {taint.SourceLine} ('{taint.SourceText}') {flowLabel} an execution sink ('{taint.SinkText}'). This runs unreviewed remote content as code.";

        return new Finding
        {
            RuleId = Id,
            OwaspCode = OwaspCode,
            Severity = severity,
            Title = taint.Flow switch
            {
                TaintFlow.DirectPipe => "Script Pipeline Taint: Fetch Piped Directly To Execution",
                TaintFlow.EncodedPipe => "Script Pipeline Taint: Fetch Decoded And Executed",
                _ => "Script Pipeline Taint: Fetch Result Executed Via Variable"
            },
            Description = description,
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
