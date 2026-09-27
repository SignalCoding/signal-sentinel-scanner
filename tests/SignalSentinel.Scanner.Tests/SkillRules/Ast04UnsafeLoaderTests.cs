// -----------------------------------------------------------------------
// <copyright file="Ast04UnsafeLoaderTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Spec: _docs/ai/specs/ast04-metadata-integrity.md, A2 (unsafe deserialisation
// in bundled scripts) and A4 (SS-043 severity: Medium for an unsafe loader
// alone, with no code-executing construct in a shipped data file). Covers
// exactly the vocabulary this task's brief names: `yaml.load` without
// SafeLoader, `yaml.unsafe_load`, `pickle.load`/`loads`, `marshal.loads`, and
// the negative controls `yaml.safe_load`/`json.load`.
//
// Not covered here (spec A2 also names these, out of this file's explicit
// scope per the task brief - flagged in the test report as a coverage gap for
// the coding agent to close): `eval` applied to parsed content, and the
// JS/PowerShell equivalents (`js-yaml` `load` with `JSON_SCHEMA` overrides,
// `Import-Clixml`).
//
// SS-043 does not exist yet; looked up by id through RuleEngine.CatalogueRules()
// exactly as Ast04CorpusTests and McpLoggingCapabilityAbsentRuleTests do, so the
// assembly still compiles and these tests fail cleanly on "rule not found"
// until the rule is implemented and registered.

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillRules;

public class Ast04UnsafeLoaderTests
{
    private const string Ss043RuleId = "SS-043";

    [Theory]
    [InlineData(
        "unsafe-yaml-load",
        "import yaml\n" +
        "def load(path):\n" +
        "    with open(path) as fh:\n" +
        "        return yaml.load(fh.read())\n")]
    [InlineData(
        "unsafe-yaml-unsafe-load",
        "import yaml\n" +
        "def load(path):\n" +
        "    with open(path) as fh:\n" +
        "        return yaml.unsafe_load(fh.read())\n")]
    [InlineData(
        "unsafe-pickle-load",
        "import pickle\n" +
        "def load(path):\n" +
        "    with open(path, 'rb') as fh:\n" +
        "        return pickle.load(fh)\n")]
    [InlineData(
        "unsafe-pickle-loads",
        "import pickle\n" +
        "def load(blob):\n" +
        "    return pickle.loads(blob)\n")]
    [InlineData(
        "unsafe-marshal-loads",
        "import marshal\n" +
        "def load(blob):\n" +
        "    return marshal.loads(blob)\n")]
    public async Task Evaluate_UnsafeLoaderAloneInBundledScript_FiresSs043AtMedium(string skillName, string script)
    {
        var context = SkillWithScript(skillName, script);

        var rule = GetRule();
        var findings = (await rule.EvaluateAsync(context)).ToList();

        findings.ShouldContain(f => f.RuleId == Ss043RuleId && f.Severity == Severity.Medium,
            $"Expected SS-043 Medium for '{skillName}' (unsafe loader alone, no data-file construct).");
    }

    [Theory]
    [InlineData(
        "safe-yaml-safe-load",
        "import yaml\n" +
        "def load(path):\n" +
        "    with open(path) as fh:\n" +
        "        return yaml.safe_load(fh.read())\n")]
    [InlineData(
        "safe-json-load",
        "import json\n" +
        "def load(path):\n" +
        "    with open(path) as fh:\n" +
        "        return json.load(fh)\n")]
    public async Task Evaluate_SafeLoaderInBundledScript_NeverFiresSs043(string skillName, string script)
    {
        var context = SkillWithScript(skillName, script);

        var rule = GetRule();
        var findings = (await rule.EvaluateAsync(context)).ToList();

        findings.ShouldNotContain(f => f.RuleId == Ss043RuleId,
            $"'{skillName}' uses only safe deserialisation APIs and must never fire {Ss043RuleId}.");
    }

    private static ScanContext SkillWithScript(string skillName, string scriptContent) => new()
    {
        Servers = [],
        Skills =
        [
            new SkillDefinition
            {
                Name = skillName,
                Description = "A skill with a bundled loader script",
                InstructionsBody = "Loads its own metadata sidecar at startup.",
                RawContent = "Loads its own metadata sidecar at startup.",
                FilePath = $"/skills/{skillName}/SKILL.md",
                Scripts =
                [
                    new BundledScript
                    {
                        RelativePath = "scripts/loader.py",
                        FullPath = $"/skills/{skillName}/scripts/loader.py",
                        Language = ScriptLanguage.Python,
                        Content = scriptContent,
                        FileSize = scriptContent.Length
                    }
                ]
            }
        ]
    };

    /// <summary>
    /// Looks the rule up by id in the authoritative catalogue rather than referencing
    /// its (not-yet-existing) concrete type. Fails clearly, naming the missing id,
    /// until the rule is implemented and registered.
    /// </summary>
    private static IRule GetRule()
    {
        var rule = RuleEngine.CatalogueRules()
            .FirstOrDefault(r => string.Equals(r.Id, Ss043RuleId, StringComparison.Ordinal));

        rule.ShouldNotBeNull(
            $"{Ss043RuleId} (Insecure Skill Metadata) is not registered in " +
            "RuleEngine.CatalogueRules() - implement and register the rule per spec A4.");

        return rule!;
    }
}
