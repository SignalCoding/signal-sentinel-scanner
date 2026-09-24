// -----------------------------------------------------------------------
// <copyright file="SkillScopeViolationShapeTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

/// <summary>
/// v3.0.2 (N1): <see cref="SkillScopeViolationRule"/> (SS-012) capability detection
/// moves from bare token lists to usage shapes (verb + short gap + target, or a
/// concrete client/call). Pins one own-words false-positive case per the noun/token
/// table in the spec, plus one genuine shape per capability that must still fire, plus
/// the filesystem purpose-declaration extension (document/file-extension synonyms).
/// Spec: _docs/ai/specs/v3.0.2-skill-noise.md N1.
/// </summary>
public class SkillScopeViolationShapeTests
{
    private static readonly SkillScopeViolationRule Rule = new();

    private const string BenignPurpose = "Formats code according to a style guide.";

    private static ScanContext MakeContext(string description, string body)
    {
        var skill = new SkillDefinition
        {
            Name = "sample",
            Description = description,
            InstructionsBody = body,
            RawContent = body,
            FilePath = "SKILL.md",
            SourcePlatform = "test"
        };
        return new ScanContext { Servers = [], Skills = [skill] };
    }

    // ---- N1 false positives: one own-words case per table row -----------------

    [Fact]
    public async Task N1_Network_BareUrlAndFetchAsVerbWithoutTarget_NoFinding()
    {
        // academy-guide, mcp-builder, web-artifacts-builder, doc-coauthoring:
        // "https" in a raw URL, "fetch" used as a bare verb with no target.
        var context = MakeContext(
            BenignPurpose,
            "See the documentation at https://example.com/guide for more information. " +
            "We could always fetch inspiration from other projects later.");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotContain(f => f.Evidence == "network access");
    }

    [Fact]
    public async Task N1_Network_RequestAsNoun_NoFinding()
    {
        // algorithmic-art, canvas-design, internal-comms, slack-gif-creator, claude-api:
        // "the user's request".
        var context = MakeContext(
            BenignPurpose,
            "Read the user's request carefully before drafting a response.");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotContain(f => f.Evidence == "network access");
    }

    [Fact]
    public async Task N1_Network_WebhookAsNoun_NoFinding()
    {
        // frontend-design: "webhook" noun mention.
        var context = MakeContext(
            BenignPurpose,
            "This skill does not create or manage a webhook of any kind.");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotContain(f => f.Evidence == "network access");
    }

    [Fact]
    public async Task N1_Shell_ShellAndExecAsBareWords_NoFinding()
    {
        // claude-api, pptx: "a shell/cURL project", "code exec" in a feature table.
        var context = MakeContext(
            BenignPurpose,
            "This is a shell/cURL project for local development.\n\n" +
            "| Feature | Support |\n| --- | --- |\n| code exec | not available |\n");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotContain(f => f.Evidence == "shell/command execution");
    }

    [Fact]
    public async Task N1_ShellAndFilesystem_SpawnSubagentAndSaveToFilesystem_NoFinding()
    {
        // skill-creator: "spawn a subagent", "save it to the filesystem".
        var context = MakeContext(
            BenignPurpose,
            "You can spawn a subagent to review the draft, then save it to " +
            "the filesystem for reference.");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotContain(f => f.Evidence == "shell/command execution");
        findings.ShouldNotContain(f => f.Evidence == "filesystem access");
    }

    [Fact]
    public async Task N1_Filesystem_FilesystemAsNoun_NoFinding()
    {
        // claude-api, skill-creator: "filesystem" noun mention.
        var context = MakeContext(
            BenignPurpose,
            "This document explains the skill's approach to the filesystem and how it is organized.");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotContain(f => f.Evidence == "filesystem access");
    }

    // ---- N1 genuine shapes: must still fire ------------------------------------

    [Fact]
    public async Task N1_Network_GenuineDownloadShape_StillFires()
    {
        var context = MakeContext(
            BenignPurpose,
            "Download the file from https://example.com/x.");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldContain(f =>
            f.RuleId == RuleConstants.Rules.SkillScopeViolation && f.Evidence == "network access");
    }

    [Fact]
    public async Task N1_Network_GenuineConcreteCurlClient_StillFires()
    {
        var context = MakeContext(
            BenignPurpose,
            "curl -X POST https://api.example.com/data");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldContain(f =>
            f.RuleId == RuleConstants.Rules.SkillScopeViolation && f.Evidence == "network access");
    }

    [Fact]
    public async Task N1_Shell_GenuineRunShellCommandShape_StillFires()
    {
        var context = MakeContext(
            BenignPurpose,
            "Run the shell command to clean the workspace.");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldContain(f =>
            f.RuleId == RuleConstants.Rules.SkillScopeViolation && f.Evidence == "shell/command execution");
    }

    [Fact]
    public async Task N1_Filesystem_GenuineWriteFilesShape_StillFires()
    {
        var context = MakeContext(
            BenignPurpose,
            "Write files to the output directory before finishing.");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldContain(f =>
            f.RuleId == RuleConstants.Rules.SkillScopeViolation && f.Evidence == "filesystem access");
    }

    // ---- N1 purpose-declaration extension --------------------------------------

    [Fact]
    public async Task N1_PurposeDeclaration_DocxAndDocumentsMentionInDescription_DeclaresFilesystemAccess()
    {
        var context = MakeContext(
            "Create Word documents from templates (.docx).",
            "Save the report to the filesystem using write_file so the user can access it later.");

        var findings = (await Rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotContain(f => f.Evidence == "filesystem access");
    }
}
