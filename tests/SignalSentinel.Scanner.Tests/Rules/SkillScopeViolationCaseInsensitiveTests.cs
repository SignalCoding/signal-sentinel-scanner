using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

/// <summary>
/// v2.3.0: case-insensitive capability matching + lemma synonyms.
/// </summary>
public class SkillScopeViolationCaseInsensitiveTests
{
    private static ScanContext MakeContext(string description, string body)
    {
        var skill = new SkillDefinition
        {
            Name = "sample",
            Description = description,
            InstructionsBody = body,
            FilePath = "SKILL.md",
            RawContent = $"---\ndescription: {description}\n---\n{body}",
            SourcePlatform = "test"
        };
        return new ScanContext { Servers = System.Array.Empty<ServerEnumeration>(), Skills = new[] { skill } };
    }

    [Fact]
    public async Task CapitalisedDescription_SatisfiesLowercaseBody_NoFinding()
    {
        var rule = new SkillScopeViolationRule();
        var ctx = MakeContext(
            description: "Makes Network requests to APIs",
            body: "The skill will issue http calls with fetch to list endpoints.");
        var findings = await rule.EvaluateAsync(ctx);
        Assert.DoesNotContain(findings, f => f.Evidence == "network access");
    }

    [Fact]
    public async Task SynonymInDescription_SatisfiesCapability_NoFinding()
    {
        var rule = new SkillScopeViolationRule();
        var ctx = MakeContext(
            description: "Monitors local filesystem for changes.",
            body: "Reads from file system and returns metadata via fs.readFile.");
        var findings = await rule.EvaluateAsync(ctx);
        Assert.DoesNotContain(findings, f => f.Evidence == "filesystem access");
    }

    [Fact]
    public async Task NoMatchingSynonym_EmitsFindingStill()
    {
        var rule = new SkillScopeViolationRule();
        var ctx = MakeContext(
            description: "Formats Python code (lints only).",
            body: "Runs http requests to fetch remote dependencies.");
        var findings = await rule.EvaluateAsync(ctx);
        Assert.Contains(findings, f => f.Evidence == "network access");
    }

    [Fact]
    public async Task EveryEmittedFinding_CarriesAstCodes()
    {
        var rule = new SkillScopeViolationRule();
        var ctx = MakeContext(
            description: "Formats python code.",
            body: "Issues curl and wget requests externally.");
        var findings = (await rule.EvaluateAsync(ctx)).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Contains("AST03", f.AstCodes));
    }
}
