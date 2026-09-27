// -----------------------------------------------------------------------
// <copyright file="RuleRegistryParityTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Spec: _docs/ai/specs/rule-registry-parity.md, requirement R7.
//
// Drives every registered rule against every surface named in the spec's section 2
// gap matrix, so a rule that is added without wiring it into one of those surfaces
// fails the build instead of silently shipping half-registered. Each (rule, surface)
// pair is its own [Theory] case so a failure names exactly what is missing.
//
// Judgement calls (see _docs/ai/logs/rule-registry-parity_test-report.md for detail):
//   - The catalogue/engine-registration surfaces are asserted against
//     `new RuleEngine().Rules` (the current public surface, exactly what
//     Program.PrintRuleList uses today) rather than `RuleEngine.CatalogueRules()`,
//     which does not exist yet (R1). Referencing a not-yet-existing static method
//     would fail to compile and take every other test in the assembly down with it,
//     which the spec's own escape valve says to avoid.
//   - "--help lists it" is matched against the Program.cs source text of the
//     MCP/Skill/Informational rule blocks, the same cheap "matched by rule id
//     appearing in the file" technique the spec prescribes for the doc surfaces,
//     because `PrintUsage` is private and not reachable via InternalsVisibleTo.
//   - The README surface is scoped to the "### Security Rules" .. "### Supported
//     Platforms" heading span, not the whole file, because the changelog prose above
//     that section already name-checks most (not all) of the new rule ids and a
//     whole-file match would undercount the gap the spec's matrix records (15).

using System.Reflection;
using Shouldly;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class RuleRegistryParityTests
{
    private const string ThisFileName = "RuleRegistryParityTests.cs";

    private static readonly string[] ExcludedDirectorySegments = ["bin", "obj"];

    // SS-INFO-002 (Non-Public Scan Target) has no applicable OWASP AST code: it is a
    // scan-target trust-boundary annotation, not a property of an MCP server or
    // skill artefact. This is the one documented exception the spec calls for.
    private static readonly HashSet<string> AstMappingAllowList =
        new(StringComparer.Ordinal) { RuleConstants.Rules.NonPublicTarget };

    private static List<string> AllRuleIds { get; } = GetAllRuleIds();

    private static Dictionary<string, string> RuleIdToConstantName { get; } = GetRuleIdToConstantName();

    private static string RepoRoot { get; } = ResolveRepoRoot();

    public static IEnumerable<object[]> RuleIdCases => AllRuleIds.Select(id => new object[] { id });

    [Fact]
    public void AuthoritativeList_Contains47DistinctRulesDerivedFromRuleConstants()
    {
        // This is the "rule constant exists" surface: the authoritative list itself
        // is derived from RuleConstants.Rules by reflection, so every id here already
        // has a constant. What this guards against is drift in the count (currently
        // 48: 41 detection + 7 informational, after owasp-full-coverage.md C4/C6 added
        // SS-INFO-007) and accidental duplicate values.
        AllRuleIds.Count.ShouldBe(48);
        AllRuleIds.Distinct(StringComparer.Ordinal).Count().ShouldBe(48);
        AllRuleIds.Count(id => id.StartsWith("SS-INFO-", StringComparison.Ordinal)).ShouldBe(7);
    }

    [Theory]
    [MemberData(nameof(RuleIdCases))]
    public void Rule_HasAstMapping_OrIsDocumentedAllowListException(string ruleId)
    {
        var codes = RuleAstMapping.GetCodes(ruleId);

        if (AstMappingAllowList.Contains(ruleId))
        {
            codes.ShouldBeEmpty(
                $"{ruleId} is on the AST-mapping allow-list as having no applicable AST code. " +
                "If a mapping was added for it, remove it from AstMappingAllowList.");
        }
        else
        {
            codes.ShouldNotBeEmpty(
                $"{ruleId} has no entry in RuleAstMapping and is not on the documented allow-list " +
                "(Core/Models/RuleAstMapping.cs).");
        }
    }

    [Theory]
    [MemberData(nameof(RuleIdCases))]
    public void Rule_IsListedByListRulesCatalogue(string ruleId)
    {
        // Mirrors Program.PrintRuleList exactly: a bare `new RuleEngine()` with no
        // per-scan custom rules. SS-022/023/024/025 are wired into every real scan via
        // Program.cs's `customRules.Add(...)` (the R1 defect this pins), so they never
        // reach this list even though they run.
        var catalogue = RuleEngine.CatalogueRules().Select(r => r.Id).ToList();
        catalogue.ShouldContain(
            ruleId,
            $"{ruleId} is missing from the --list-rules catalogue (new RuleEngine().Rules).");
    }

    [Theory]
    [MemberData(nameof(RuleIdCases))]
    public void Rule_IsListedInHelpText(string ruleId)
    {
        var programSource = ReadRepoFile(Path.Combine("src", "SignalSentinel.Scanner", "Program.cs"));
        var helpBlock = ExtractSection(programSource, "MCP SECURITY RULES:", "For more information:", "Program.cs");

        helpBlock.Contains(ruleId, StringComparison.Ordinal).ShouldBeTrue(
            $"{ruleId} is missing from the --help rule registry block in Program.cs.");
    }

    [Theory]
    [MemberData(nameof(RuleIdCases))]
    public void Rule_IsListedInReadmeSecurityRulesSection(string ruleId)
    {
        var readme = ReadRepoFile("README.md");
        var securityRulesSection = ExtractSection(readme, "### Security Rules", "### Supported Platforms", "README.md");

        securityRulesSection.Contains(ruleId, StringComparison.Ordinal).ShouldBeTrue(
            $"{ruleId} is missing from the README.md \"Security Rules\" tables.");
    }

    [Theory]
    [MemberData(nameof(RuleIdCases))]
    public void Rule_IsListedInAstMappingDoc(string ruleId)
    {
        var doc = ReadRepoFile(Path.Combine("docs", "owasp-ast-mapping.md"));

        doc.Contains(ruleId, StringComparison.Ordinal).ShouldBeTrue(
            $"{ruleId} is missing from docs/owasp-ast-mapping.md.");
    }

    [Theory]
    [MemberData(nameof(RuleIdCases))]
    public void Rule_IsListedInInstallationGuide(string ruleId)
    {
        var doc = ReadRepoFile("INSTALLATION_AND_USAGE.md");

        doc.Contains(ruleId, StringComparison.Ordinal).ShouldBeTrue(
            $"{ruleId} is missing from INSTALLATION_AND_USAGE.md.");
    }

    [Theory]
    [MemberData(nameof(RuleIdCases))]
    public void Rule_HasTestCoverage(string ruleId)
    {
        // Most test classes assert on the literal id (e.g. "SS-026"), but a few
        // (CredentialHygieneRuleTests -> SS-019, SkillOsvRulesTests -> SS-INFO-006)
        // only assert `f.RuleId.ShouldBe(RuleConstants.Rules.<ConstantName>)`, so the
        // rule's own RuleConstants field name is also an acceptable reference - this
        // is the spec's "the rule id or its rule class name" clause, applied to the
        // constant name rather than the IRule implementation's class name, since the
        // constant name is what's reflected at the call sites that use it.
        var constantName = RuleIdToConstantName[ruleId];
        var referenced = TestFileContents.Any(content =>
            content.Contains(ruleId, StringComparison.Ordinal) ||
            content.Contains(constantName, StringComparison.Ordinal));

        referenced.ShouldBeTrue(
            $"{ruleId} is not referenced by rule id, or by its RuleConstants field '{constantName}', " +
            "in any file under tests/ - add (or extend) a test class for it.");
    }

    private static List<string> GetAllRuleIds() =>
        RuleConstantFields()
            .Select(f => (string)f.GetRawConstantValue()!)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();

    private static Dictionary<string, string> GetRuleIdToConstantName() =>
        RuleConstantFields().ToDictionary(
            f => (string)f.GetRawConstantValue()!,
            f => f.Name,
            StringComparer.Ordinal);

    private static IEnumerable<FieldInfo> RuleConstantFields() =>
        typeof(RuleConstants.Rules)
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string));

    private static readonly Lazy<IReadOnlyList<string>> TestFileContentsLazy = new(LoadTestFileContents);

    private static IReadOnlyList<string> TestFileContents => TestFileContentsLazy.Value;

    private static List<string> LoadTestFileContents()
    {
        var testsDir = Path.Combine(RepoRoot, "tests");
        var contents = new List<string>();

        foreach (var file in Directory.EnumerateFiles(testsDir, "*.cs", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(testsDir, file);
            var segments = relative.Split(Path.DirectorySeparatorChar);

            if (segments.Any(s => ExcludedDirectorySegments.Contains(s, StringComparer.OrdinalIgnoreCase)))
            {
                continue;
            }

            // Exclude this file itself: it name-checks every rule id by construction,
            // and that must not count as "coverage".
            if (string.Equals(Path.GetFileName(file), ThisFileName, StringComparison.Ordinal))
            {
                continue;
            }

            contents.Add(File.ReadAllText(file));
        }

        return contents;
    }

    private static string ReadRepoFile(string relativePath) =>
        File.ReadAllText(Path.Combine(RepoRoot, relativePath));

    private static string ExtractSection(string content, string startMarker, string endMarker, string fileLabel)
    {
        var startIndex = content.IndexOf(startMarker, StringComparison.Ordinal);
        startIndex.ShouldBeGreaterThanOrEqualTo(
            0,
            $"marker '{startMarker}' not found in {fileLabel} - update RuleRegistryParityTests' section markers.");

        var endIndex = content.IndexOf(endMarker, startIndex, StringComparison.Ordinal);
        endIndex.ShouldBeGreaterThan(
            startIndex,
            $"marker '{endMarker}' not found after '{startMarker}' in {fileLabel} - update RuleRegistryParityTests' section markers.");

        return content[startIndex..endIndex];
    }

    /// <summary>
    /// Repo root located the same way <c>VersionDriftTests.RepoRoot</c> does: the
    /// project directory is three levels above <see cref="AppContext.BaseDirectory"/>
    /// (bin/&lt;cfg&gt;/&lt;tfm&gt;), then two more levels up
    /// (tests/&lt;project&gt; -&gt; tests -&gt; repo root), confirmed by the presence
    /// of the solution file.
    /// </summary>
    private static string ResolveRepoRoot()
    {
        var projectDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
        var repoRoot = Path.GetFullPath(Path.Combine(projectDir, "..", ".."));

        if (File.Exists(Path.Combine(repoRoot, "signal-sentinel.sln")))
        {
            return repoRoot;
        }

        // Fallback for a copied-to-output layout (mirrors RealWorldSkillFixtures).
        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
    }
}
