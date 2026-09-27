// -----------------------------------------------------------------------
// <copyright file="Ast04CorpusTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Spec: _docs/ai/specs/ast04-metadata-integrity.md, A4/acceptance item 2, as
// corrected by section 6/C1-C2 and section 7/D3 (both "after implementation"
// amendments). The labelled corpus (Fixtures/Ast04Corpus, provenance in
// NOTICE.md) is the oracle: every vulnerable fixture must be detected by its
// correct closure route, and every control fixture must be silent for SS-043.
//
// D3 ruling (section 7): the original test brief asked this harness to assert
// SS-043 on all five V* fixtures, contradicting section 6/C2, which assigns V7
// and V9 to SS-017. That contradiction was flagged rather than guessed at when
// this harness was first written; the ruling is that the implementation is
// spec-faithful and the harness assertion was wrong. Per fixture:
//   - V1, V3, V5 -> SS-043, severities High/High/Medium (section 6/C1, verified
//     against the built binary in section 7).
//   - V9 -> SS-017 (risk-tier floor derived from declared permissions, A1).
//   - V7 -> a finding from *any* rule. Its principled route (comparing a
//     manifest's egress allowlist against the hosts bundled scripts actually
//     reach) is deferred to spec section 7/D2 as a follow-up, not this branch;
//     today it is caught only incidentally, via SS-014.
//
// SS-043 did not exist when this file was first written; the rule lookup-by-id
// helper (mirrors McpLoggingCapabilityAbsentRuleTests) is kept so the id stays
// the single source of truth rather than a concrete-type reference.

using System.Globalization;
using System.Text;
using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

public class Ast04CorpusTests
{
    private const string Ss043RuleId = "SS-043";
    private const string Ss017RuleId = "SS-017";

    public static TheoryData<string> ControlFixtureNames()
    {
        var data = new TheoryData<string>();
        foreach (var name in Ast04CorpusFixtures.ControlFixtures)
        {
            data.Add(name);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(ControlFixtureNames))]
    public async Task ControlFixture_ProducesZeroSs043Findings(string fixtureName)
    {
        var findings = await ScanFixtureAsync(fixtureName, Ss043RuleId).ConfigureAwait(true);
        var offenders = findings.Where(f => f.RuleId == Ss043RuleId).ToList();

        offenders.ShouldBeEmpty(
            $"Expected zero {Ss043RuleId} findings on control fixture '{fixtureName}'. " + Describe(offenders));
    }

    // ---- Per-fixture closure route (spec section 6/C1-C2, section 7/D3) ---

    [Fact]
    public async Task V1_FiresSs043AtHighSeverity()
    {
        // Confirmed by reading the fixture: metadata.yaml carries the
        // `!!python/object/apply:os.system` tag AND loader.py calls
        // `yaml.load()` with no SafeLoader - genuinely both halves.
        var findings = await ScanFixtureAsync("V1-yaml-frontmatter-injection", Ss043RuleId).ConfigureAwait(true);

        findings.ShouldContain(f => f.RuleId == Ss043RuleId && f.Severity == Severity.High,
            "Expected SS-043 High on V1 (both halves present). " + Describe(findings));
    }

    [Fact]
    public async Task V3_FiresSs043AtHighSeverity()
    {
        // Section 6/C1: V3's construct is prototype pollution (a __proto__ key
        // in shipped JSON), consumed by a plain deepMerge in a bundled script -
        // the second "both halves" family (construct + consumer), not the
        // deserialisation one. Verified High against the built binary (section 7).
        var findings = await ScanFixtureAsync("V3-json-metadata-injection", Ss043RuleId).ConfigureAwait(true);

        findings.ShouldContain(f => f.RuleId == Ss043RuleId && f.Severity == Severity.High,
            "Expected SS-043 High on V3 (construct + consumer present). " + Describe(findings));
    }

    [Fact]
    public async Task V5_FiresSs043AtMediumSeverity()
    {
        // Section 6/C1: V5's construct is parser ambiguity (a duplicate
        // [permissions] TOML table) with no consuming script at all - the
        // construct-alone Medium band. Verified against the built binary (section 7).
        var findings = await ScanFixtureAsync("V5-toml-metadata-injection", Ss043RuleId).ConfigureAwait(true);

        findings.ShouldContain(f => f.RuleId == Ss043RuleId && f.Severity == Severity.Medium,
            "Expected SS-043 Medium on V5 (construct alone, no consumer). " + Describe(findings));
    }

    [Fact]
    public async Task V7_FiresAnyRuleIncidentallyPendingD2()
    {
        // Section 7/D3: V7 ("permission understating" - the manifest's egress
        // allowlist names one host, the bundled script reaches a different,
        // undeclared one) has no principled detector on this branch. It is
        // caught only incidentally, today via SS-014, pending spec section
        // 7/D2 (compare a manifest's egress allowlist against the hosts
        // bundled scripts actually reach - a new detection, not an extension
        // of SS-043 or SS-017, and explicitly out of scope for this branch).
        var findings = await ScanFixtureWithAllRulesAsync("V7-permission-understating").ConfigureAwait(true);

        findings.ShouldNotBeEmpty(
            "Expected V7 to be caught by at least one rule (today incidentally, via SS-014). " +
            Describe(findings));
    }

    [Fact]
    public async Task V9_FiresSs017()
    {
        // Section 6/C2: risk-tier spoofing belongs to SS-017 (A1's floor
        // derived from declared permissions), not SS-043.
        var findings = await ScanFixtureAsync("V9-risk-tier-spoofing", Ss017RuleId).ConfigureAwait(true);

        findings.ShouldContain(f => f.RuleId == Ss017RuleId,
            "Expected SS-017 to fire on V9 (risk-tier spoofing). " + Describe(findings));
    }

    // ---- A5: the existing real-world corpus must stay at zero SS-043 -----

    [Fact]
    public async Task RealWorldSkillCorpus_ProducesZeroSs043Findings()
    {
        Directory.Exists(RealWorldSkillFixtures.Dir).ShouldBeTrue(
            "Corpus directory not found: " + RealWorldSkillFixtures.Dir);

        var skills = await SkillReader.ReadDirectoryAsync(RealWorldSkillFixtures.Dir).ConfigureAwait(true);
        var context = new ScanContext { Servers = [], Skills = skills };

        var rule = GetRule(Ss043RuleId);
        var findings = (await rule.EvaluateAsync(context).ConfigureAwait(true)).ToList();

        findings.ShouldBeEmpty(Describe(findings));
    }

    private static async Task<List<Finding>> ScanFixtureAsync(string fixtureName, string ruleId)
    {
        var skill = await LoadFixtureSkillAsync(fixtureName).ConfigureAwait(true);
        var context = new ScanContext { Servers = [], Skills = [skill] };

        var rule = GetRule(ruleId);
        return (await rule.EvaluateAsync(context).ConfigureAwait(true)).ToList();
    }

    private static async Task<List<Finding>> ScanFixtureWithAllRulesAsync(string fixtureName)
    {
        var skill = await LoadFixtureSkillAsync(fixtureName).ConfigureAwait(true);
        var context = new ScanContext { Servers = [], Skills = [skill] };

        var findings = new List<Finding>();
        foreach (var rule in RuleEngine.CatalogueRules())
        {
            findings.AddRange(await rule.EvaluateAsync(context).ConfigureAwait(true));
        }

        return findings;
    }

    private static async Task<SkillDefinition> LoadFixtureSkillAsync(string fixtureName)
    {
        var dir = Ast04CorpusFixtures.FixtureDir(fixtureName);
        Directory.Exists(dir).ShouldBeTrue("Fixture directory not found: " + dir);

        var skill = await SkillReader.ReadAsync(Path.Combine(dir, "SKILL.md")).ConfigureAwait(true);
        skill.ShouldNotBeNull("Failed to parse SKILL.md for fixture: " + fixtureName);

        return skill!;
    }

    /// <summary>
    /// Looks a rule up by id in the authoritative catalogue rather than referencing
    /// its concrete type. For SS-043, which did not exist when this harness was
    /// first written, this fails cleanly, naming the missing id, until the rule is
    /// implemented and registered.
    /// </summary>
    private static IRule GetRule(string ruleId)
    {
        var rule = RuleEngine.CatalogueRules()
            .FirstOrDefault(r => string.Equals(r.Id, ruleId, StringComparison.Ordinal));

        rule.ShouldNotBeNull(
            $"{ruleId} is not registered in RuleEngine.CatalogueRules().");

        return rule!;
    }

    private static string Describe(IEnumerable<Finding> findings)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Findings (ruleId severity skill | title | evidence):");
        foreach (var f in findings.OrderBy(f => f.RuleId, StringComparer.Ordinal).ThenBy(f => f.Severity))
        {
            builder.AppendLine(CultureInfo.InvariantCulture,
                $"  {f.RuleId} {f.Severity} {f.ServerName} | {f.Title} | {f.Evidence}");
        }

        return builder.ToString();
    }
}
