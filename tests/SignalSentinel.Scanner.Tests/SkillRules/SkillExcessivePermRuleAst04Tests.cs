// -----------------------------------------------------------------------
// <copyright file="SkillExcessivePermRuleAst04Tests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Spec: _docs/ai/specs/ast04-metadata-integrity.md, A1. Extends
// SkillExcessivePermRule's risk_tier vocabulary to the Universal Skill Format
// `L0`..`L3` ladder (and bare numeric `0`..`3`) and derives the implied floor
// from declared permissions (`shell: true`, non-empty `files.write`, non-empty
// `network.allow`), not only from prose-observed danger signals.
//
// Kept separate from SkillExcessivePermRuleTests.cs (the existing v2.5.0/G15c
// suite) so that file's green baseline is never at risk of an edit mistake
// here - per the task brief, those tests must stay green throughout.
//
// Frontmatter is supplied directly on SkillDefinition.ExtraFrontmatter using
// the flat-dotted-key convention the rule already reads (see its existing
// "network.allow" check) rather than through FrontmatterParser, mirroring
// SkillExcessivePermRuleTests' own construction style. Note for the coding
// agent: the vendored AST04 corpus fixtures (Fixtures/Ast04Corpus) declare
// these same permissions in nested YAML block form
// (`permissions:\n  shell: true`), which FrontmatterParser does not currently
// surface into ExtraFrontmatter at all (ParseFields only matches column-0
// keys). That parser gap is out of scope for this rule-level test file but is
// flagged in the test report - it affects whether the Ast04CorpusTests V7/V9
// cases can ever go green via SkillReader without separate parser work.

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

public class SkillExcessivePermRuleAst04Tests
{
    private readonly SkillExcessivePermRule _rule = new();

    private const string DangerousBody = "Read any file on the system to build an index.";

    // ---- L0..L3 vocabulary, low end ---------------------------------------

    [Theory]
    [InlineData("L0")]
    [InlineData("0")]
    [InlineData("L1")]
    [InlineData("1")]
    public async Task Evaluate_LowFormRiskTierWithDangerSignal_ReturnsHighMismatchFinding(string riskTier)
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "understated-skill",
            Description = "Looks harmless",
            InstructionsBody = DangerousBody,
            RawContent = DangerousBody,
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string> { ["risk_tier"] = riskTier }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.High &&
            f.Title.Contains("Risk Tier Understated", StringComparison.Ordinal),
            $"risk_tier: {riskTier} should be recognised as a low-tier self-declaration.");
    }

    // ---- L0..L3 vocabulary, high end ---------------------------------------

    [Theory]
    [InlineData("L2")]
    [InlineData("2")]
    [InlineData("L3")]
    [InlineData("3")]
    public async Task Evaluate_HighFormRiskTierWithDangerSignal_DoesNotFireMismatchOrMissingFindings(string riskTier)
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "honest-skill",
            Description = "Declares its own high risk",
            InstructionsBody = DangerousBody,
            RawContent = DangerousBody,
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string> { ["risk_tier"] = riskTier }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Risk Tier", StringComparison.Ordinal),
            $"risk_tier: {riskTier} should be recognised as a high-tier self-declaration.");
    }

    // ---- floor derived from declared permissions (A1, the worked example) --

    [Fact]
    public async Task Evaluate_L0WithDeclaredShellTrue_ReturnsHighMismatchFinding()
    {
        // Spec A1's own worked example: "risk_tier: L0 with shell: true is a
        // finding" - with no prose danger signal at all, the declared
        // permission alone must raise the implied floor.
        var context = CreateContext(new SkillDefinition
        {
            Name = "shell-understated-skill",
            Description = "Declares no risk but requests shell",
            InstructionsBody = "Runs a helper script.",
            RawContent = "Runs a helper script.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string>
            {
                ["risk_tier"] = "L0",
                ["shell"] = "true"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.High &&
            f.Title.Contains("Risk Tier Understated", StringComparison.Ordinal),
            "Declared 'shell: true' alone should raise the implied floor above L0.");
    }

    // v3.1.1 (R1, ss017-scoped-declarations): superseded by the spec's own
    // reproduction table. A1 (above) raised the floor from the *presence* of a
    // declared files.write/network.allow scope; the benchmark run on main
    // found that this punished an honest, narrow, enumerated allowlist the
    // same as a wildcard. The floor now rises only for an *unbounded* entry
    // ("*", "/", "~", ".."/CIDR-all/wildcard-domain - see
    // DeclaredPermissionScope). These two cases now use an unbounded entry so
    // they still exercise "declared permission alone raises the floor";
    // the bounded/narrow counterparts are covered immediately below.

    [Fact]
    public async Task Evaluate_L0WithDeclaredUnboundedFilesWrite_ReturnsHighMismatchFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "write-understated-skill",
            Description = "Declares no risk but requests an unbounded write scope",
            InstructionsBody = "Saves a report.",
            RawContent = "Saves a report.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string>
            {
                ["risk_tier"] = "L0",
                ["files.write"] = "[*]"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.High &&
            f.Title.Contains("Risk Tier Understated", StringComparison.Ordinal),
            "An unbounded declared 'files.write' scope alone should raise the implied floor above L0.");
    }

    [Fact]
    public async Task Evaluate_L0WithDeclaredNarrowFilesWrite_DoesNotFireMismatchFinding()
    {
        // R1's worked example: an enumerated relative path is a scoped, honest
        // declaration and must not be treated the same as a wildcard.
        var context = CreateContext(new SkillDefinition
        {
            Name = "write-scoped-skill",
            Description = "Declares no risk and requests a narrow write scope",
            InstructionsBody = "Saves a report.",
            RawContent = "Saves a report.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string>
            {
                ["risk_tier"] = "L0",
                ["files.write"] = "[reports/summary.md]"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Risk Tier", StringComparison.Ordinal),
            "A single enumerated relative path is a scoped grant and must not raise the implied floor.");
    }

    [Fact]
    public async Task Evaluate_L0WithDeclaredUnboundedNetworkAllow_ReturnsHighMismatchFinding()
    {
        var context = CreateContext(new SkillDefinition
        {
            Name = "network-understated-skill",
            Description = "Declares no risk but requests unbounded network egress",
            InstructionsBody = "Fetches a forecast.",
            RawContent = "Fetches a forecast.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string>
            {
                ["risk_tier"] = "L0",
                ["network.allow"] = "[*]"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldContain(f =>
            f.Severity == Severity.High &&
            f.Title.Contains("Risk Tier Understated", StringComparison.Ordinal),
            "An unbounded declared 'network.allow' scope alone should raise the implied floor above L0.");
    }

    [Fact]
    public async Task Evaluate_L0WithDeclaredNarrowNetworkAllow_DoesNotFireMismatchFinding()
    {
        // R1's worked example (spec reproduction table): a single enumerated
        // host is a scoped, honest declaration and must not be treated the
        // same as a wildcard.
        var context = CreateContext(new SkillDefinition
        {
            Name = "network-scoped-skill",
            Description = "Declares no risk and requests a narrow network scope",
            InstructionsBody = "Fetches a forecast.",
            RawContent = "Fetches a forecast.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string>
            {
                ["risk_tier"] = "L0",
                ["network.allow"] = "[api.weather.example]"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Risk Tier", StringComparison.Ordinal),
            "A single enumerated host is a scoped grant and must not raise the implied floor.");
    }

    [Fact]
    public async Task Evaluate_L3WithDeclaredShellTrue_DoesNotFireMismatchFinding()
    {
        // The control shape: an honestly-declared high tier matching (or
        // exceeding) the floor its own declared permissions imply.
        var context = CreateContext(new SkillDefinition
        {
            Name = "honest-shell-skill",
            Description = "Declares its own high risk and requests shell",
            InstructionsBody = "Runs a helper script.",
            RawContent = "Runs a helper script.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string>
            {
                ["risk_tier"] = "L3",
                ["shell"] = "true"
            }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Risk Tier", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Evaluate_L0WithNoDeclaredPermissionsAndNoProseSignal_DoesNotFireRiskTierFindings()
    {
        // Baseline: L0 with nothing raising the floor and no prose danger
        // signal must not fire at all (guards against over-firing once the
        // vocabulary/floor-derivation extension lands).
        var context = CreateContext(new SkillDefinition
        {
            Name = "genuinely-low-skill",
            Description = "Genuinely low risk and says so",
            InstructionsBody = "Help the user write better code.",
            RawContent = "Help the user write better code.",
            FilePath = "/skills/test/SKILL.md",
            ExtraFrontmatter = new Dictionary<string, string> { ["risk_tier"] = "L0" }
        });

        var findings = (await _rule.EvaluateAsync(context)).ToList();
        findings.ShouldNotContain(f => f.Title.Contains("Risk Tier", StringComparison.Ordinal));
    }

    private static ScanContext CreateContext(params SkillDefinition[] skills) =>
        new() { Servers = [], Skills = skills };
}
