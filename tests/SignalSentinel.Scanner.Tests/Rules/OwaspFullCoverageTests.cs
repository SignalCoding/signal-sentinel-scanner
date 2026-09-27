// -----------------------------------------------------------------------
// <copyright file="OwaspFullCoverageTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Spec: _docs/ai/specs/owasp-full-coverage.md.
//
// C1/C2/C3 pin the three specific remappings the spec calls for. C5 is the coverage
// guard: it derives the full ASI/AST/MCP category lists by reflection over the
// OwaspAsiCodes/OwaspAstCodes/OwaspMcpCodes constant classes (never a hard-coded count
// of ten), so a newly defined category will fail this test until some rule claims it.
//
// Judgement calls:
//   - "Claimed by a rule" for ASI codes means either the rule's own singular OwaspCode
//     equals the category, OR (for SS-010 specifically) one of its emitted attack
//     paths' OwaspCodes includes it - this is how the spec says ASI08 is claimed, since
//     no rule's own OwaspCode is ever ASI08.
//   - RuleEngine.CatalogueRules() (added in #86) is the rule set, per the brief.
//   - This file never references the not-yet-existing SS-INFO-007 rule class; that
//     coverage is exercised separately in McpLoggingCapabilityAbsentRuleTests.cs via
//     the registry lookup pattern, so its absence contributes to (rather than blocks)
//     this file's own red state for ASI10/AST08/MCP10 claims that rule would supply.

using System.Reflection;
using Shouldly;
using SignalSentinel.Core;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class OwaspFullCoverageTests
{
    // ---------------------------------------------------------------- C1 (ASI08 via SS-010)

    [Fact]
    public async Task CrossServerAttackPath_DataExfiltrationPath_IncludesAsi08()
    {
        var rule = new CrossServerAttackPathRule();
        var ctx = CrossServerExfiltrationFixture();

        await rule.EvaluateAsync(ctx).ConfigureAwait(true);

        rule.DetectedAttackPaths.ShouldNotBeEmpty();
        var exfilPath = rule.DetectedAttackPaths.First(p => p.OwaspCodes.Contains(OwaspAsiCodes.ASI09));
        exfilPath.OwaspCodes.ShouldContain(
            OwaspAsiCodes.ASI08,
            "an attack path spanning two servers is a fault propagating via automation " +
            "(ASI08 Cascading Failures), per spec owasp-full-coverage.md C1.");
    }

    [Fact]
    public void CrossServerAttackPathRule_SingularOwaspCode_RemainsAsi02()
    {
        // C1 is explicitly additive: the rule's own single-valued OwaspCode must not
        // change to ASI08, only the attack path's OwaspCodes list grows.
        new CrossServerAttackPathRule().OwaspCode.ShouldBe(OwaspAsiCodes.ASI02);
    }

    // ---------------------------------------------------------------- C2 (AST09 via SS-024)

    [Fact]
    public void SkillIntegrityRule_AstMapping_IncludesAst09()
    {
        var codes = RuleAstMapping.GetCodes(RuleConstants.Rules.SkillIntegrityVerification);

        codes.ShouldContain(
            OwaspAstCodes.AST09,
            "a skill shipping with no signature/integrity artefact is the absence of " +
            "change-management and review made observable (AST09 No Governance), per spec C2.");
    }

    [Fact]
    public void SkillIntegrityRule_AstMapping_RemainsAdditive()
    {
        // C2 must not remove the existing AST02/AST07 claims.
        var codes = RuleAstMapping.GetCodes(RuleConstants.Rules.SkillIntegrityVerification);

        codes.ShouldContain(OwaspAstCodes.AST02);
        codes.ShouldContain(OwaspAstCodes.AST07);
    }

    // ---------------------------------------------------------------- C3 (MCP04 via SS-041)

    [Fact]
    public void GetCorrespondingMcpCode_ServerSourceSink_ReturnsMcp04()
    {
        OwaspMcpCodes.GetCorrespondingMcpCode(RuleConstants.Rules.ServerSourceSink).ShouldBe(
            OwaspMcpCodes.MCP04,
            "a dangerous sink in server source reachable from a tool parameter is tool " +
            "argument injection (MCP04), per spec C3.");
    }

    // ---------------------------------------------------------------- C5 (coverage guard)

    [Fact]
    public async Task EveryAsiCategory_IsClaimedByAtLeastOneRuleOrAttackPath()
    {
        var claimed = await ClaimedAsiCodesAsync();
        var unclaimed = AllAsiCodes.Where(c => !claimed.Contains(c)).ToList();

        unclaimed.ShouldBeEmpty(
            $"ASI categories claimed by no rule and no attack path: {string.Join(", ", unclaimed)}");
    }

    // Spec owasp-full-coverage.md section 5 (the amendment): AST10 (Cross-Platform
    // Reuse - "skill mixes incompatible platform semantics unsafely") is a single,
    // named, documented exception. It cannot be closed by a mapping like the other
    // four gaps; it would need a new detection designed from scratch, with its own
    // spec and false-positive analysis. This is the only exception the guard grants,
    // and it is printed in the failure message below so it stays visible rather than
    // silently tolerated. Any *other* category that becomes unclaimed still fails.
    private const string DocumentedAstException = OwaspAstCodes.AST10;

    private const string DocumentedAstExceptionReason =
        "AST10 (Cross-Platform Reuse) is not detected by any shipped rule and is not " +
        "closable by remapping, unlike ASI08/AST09/MCP04/MCP10 - see spec " +
        "owasp-full-coverage.md section 5 for the reasoning and the decision to leave " +
        "it as a single documented exception rather than force a mapping.";

    [Fact]
    public void EveryAstCategory_IsClaimedByAtLeastOneRule()
    {
        var claimed = ClaimedAstCodes();
        var unclaimed = AllAstCodes
            .Where(c => !claimed.Contains(c) && !string.Equals(c, DocumentedAstException, StringComparison.Ordinal))
            .ToList();

        unclaimed.ShouldBeEmpty(
            $"AST categories claimed by no rule's RuleAstMapping entry: {string.Join(", ", unclaimed)}. " +
            $"(Documented exception: {DocumentedAstException} - {DocumentedAstExceptionReason})");
    }

    [Fact]
    public void EveryMcpCategory_IsClaimedByAtLeastOneRule()
    {
        var claimed = ClaimedMcpCodes();
        var unclaimed = AllMcpCodes.Where(c => !claimed.Contains(c)).ToList();

        unclaimed.ShouldBeEmpty(
            $"MCP categories claimed by no rule via GetCorrespondingMcpCode: {string.Join(", ", unclaimed)}");
    }

    // ---------------------------------------------------------------------- fixtures/helpers

    private static List<string> AllAsiCodes { get; } = GetConstCodes(typeof(OwaspAsiCodes));

    private static List<string> AllAstCodes { get; } = GetConstCodes(typeof(OwaspAstCodes));

    private static List<string> AllMcpCodes { get; } = GetConstCodes(typeof(OwaspMcpCodes));

    private static List<string> GetConstCodes(Type type) =>
        type.GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .OrderBy(c => c, StringComparer.Ordinal)
            .ToList();

    private static async Task<HashSet<string>> ClaimedAsiCodesAsync()
    {
        var claimed = new HashSet<string>(StringComparer.Ordinal);

        foreach (var rule in RuleEngine.CatalogueRules())
        {
            claimed.Add(rule.OwaspCode);
        }

        // Attack paths can carry ASI codes beyond a rule's own singular OwaspCode
        // (ASI08 is only ever claimed this way - see C1).
        var pathRule = new CrossServerAttackPathRule();
        await pathRule.EvaluateAsync(CrossServerExfiltrationFixture()).ConfigureAwait(true);
        foreach (var path in pathRule.DetectedAttackPaths)
        {
            foreach (var code in path.OwaspCodes)
            {
                claimed.Add(code);
            }
        }

        return claimed;
    }

    private static HashSet<string> ClaimedAstCodes()
    {
        var claimed = new HashSet<string>(StringComparer.Ordinal);

        foreach (var rule in RuleEngine.CatalogueRules())
        {
            foreach (var code in RuleAstMapping.GetCodes(rule.Id))
            {
                claimed.Add(code);
            }
        }

        return claimed;
    }

    private static HashSet<string> ClaimedMcpCodes()
    {
        var claimed = new HashSet<string>(StringComparer.Ordinal);

        foreach (var rule in RuleEngine.CatalogueRules())
        {
            var code = OwaspMcpCodes.GetCorrespondingMcpCode(rule.Id);
            if (code is not null)
            {
                claimed.Add(code);
            }
        }

        return claimed;
    }

    /// <summary>
    /// Two connected servers whose tools trigger CrossServerAttackPathRule's Data
    /// Exfiltration path (ReadFile capability on one server, NetworkAccess on the
    /// other) - the fixture shared by C1 and the C5 ASI coverage guard.
    /// </summary>
    private static ScanContext CrossServerExfiltrationFixture() => new()
    {
        Servers =
        [
            new ServerEnumeration
            {
                ServerConfig = new McpServerConfig { Name = "files-server" },
                ServerName = "files-server",
                Transport = "stdio",
                ConnectionSuccessful = true,
                Tools = [new McpToolDefinition { Name = "read_file", Description = "Read file content from local disk" }]
            },
            new ServerEnumeration
            {
                ServerConfig = new McpServerConfig { Name = "net-server" },
                ServerName = "net-server",
                Transport = "stdio",
                ConnectionSuccessful = true,
                Tools = [new McpToolDefinition { Name = "send_data", Description = "Send data to a remote network endpoint via http" }]
            }
        ]
    };
}
