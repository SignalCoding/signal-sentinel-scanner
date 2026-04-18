using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using SignalSentinel.Scanner.Rules.SkillRules;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

/// <summary>
/// v2.3.0 fix #22:
///   (a) SS-012 honours YAML <c>capabilities:</c> block as authoritative
///   (b) Lemma table extended with disk/volume/mount/proc/sys synonyms
/// </summary>
public class SkillScopeViolationYamlTests
{
    private static ScanContext MakeContext(SkillDefinition skill) =>
        new() { Servers = System.Array.Empty<ServerEnumeration>(), Skills = new[] { skill } };

    private static SkillDefinition MakeSkill(
        string description, string body, IReadOnlyList<string>? capabilities = null) =>
        new()
        {
            Name = "sample",
            Description = description,
            InstructionsBody = body,
            FilePath = "SKILL.md",
            RawContent = "---\ndescription: " + description + "\n---\n" + body,
            SourcePlatform = "test",
            Capabilities = capabilities ?? System.Array.Empty<string>()
        };

    [Fact]
    public async Task YamlCapabilities_ReadFilesystem_SuppressesFilesystemFinding()
    {
        var rule = new SkillScopeViolationRule();
        var skill = MakeSkill(
            description: "Formats python code.",
            body: "Reads /proc/meminfo and writes output via fs.writeFile.",
            capabilities: new[] { "read-filesystem" });

        var findings = (await rule.EvaluateAsync(MakeContext(skill))).ToList();

        Assert.DoesNotContain(findings, f => f.Evidence == "filesystem access");
    }

    [Fact]
    public async Task YamlCapabilities_Network_SuppressesNetworkFinding()
    {
        var rule = new SkillScopeViolationRule();
        var skill = MakeSkill(
            description: "Formats code",
            body: "Issues fetch and https requests to external APIs.",
            capabilities: new[] { "network" });

        var findings = (await rule.EvaluateAsync(MakeContext(skill))).ToList();

        Assert.DoesNotContain(findings, f => f.Evidence == "network access");
    }

    [Fact]
    public async Task YamlCapabilities_UnrelatedCapability_DoesNotSuppressOtherClasses()
    {
        // Declaring read-filesystem must NOT accidentally suppress a network finding.
        var rule = new SkillScopeViolationRule();
        var skill = MakeSkill(
            description: "Formats code",
            body: "Issues fetch and https requests to external APIs.",
            capabilities: new[] { "read-filesystem" });

        var findings = (await rule.EvaluateAsync(MakeContext(skill))).ToList();

        Assert.Contains(findings, f => f.Evidence == "network access");
    }

    [Fact]
    public async Task DiskAliasInDescription_SatisfiesFilesystem()
    {
        // The sentinel-monitor case: description says "disk/memory/CPU", body
        // uses "filesystem" terminology. Without YAML capabilities, the extended
        // lemma table should still recognise the synonym.
        var rule = new SkillScopeViolationRule();
        var skill = MakeSkill(
            description: "Handles user queries about VPS system health, disk/memory/CPU, and Docker container status.",
            body: "Requires filesystem access for /proc reads via fs.readFile.");

        var findings = (await rule.EvaluateAsync(MakeContext(skill))).ToList();

        Assert.DoesNotContain(findings, f => f.Evidence == "filesystem access");
    }

    [Fact]
    public async Task ProcAliasInDescription_SatisfiesFilesystem()
    {
        var rule = new SkillScopeViolationRule();
        var skill = MakeSkill(
            description: "Monitors /proc and /sys virtual filesystems.",
            body: "Calls fs.readFile and readFile on specific /proc paths.");

        var findings = (await rule.EvaluateAsync(MakeContext(skill))).ToList();

        Assert.DoesNotContain(findings, f => f.Evidence == "filesystem access");
    }

    [Fact]
    public void FrontmatterParser_InlineListCapabilities_ParsesCorrectly()
    {
        var content = "---\nname: test\ncapabilities: [read-filesystem, \"read-docker-socket\", network]\n---\nbody";
        var parsed = FrontmatterParser.Parse(content);
        var caps = parsed.GetListField("capabilities");

        Assert.Equal(3, caps.Count);
        Assert.Contains("read-filesystem", caps);
        Assert.Contains("read-docker-socket", caps);
        Assert.Contains("network", caps);
    }

    [Fact]
    public void FrontmatterParser_BlockListCapabilities_ParsesCorrectly()
    {
        var content = "---\nname: test\ncapabilities:\n  - read-filesystem\n  - \"read-docker-socket\"\n  - network\n---\nbody";
        var parsed = FrontmatterParser.Parse(content);
        var caps = parsed.GetListField("capabilities");

        Assert.True(caps.Count == 3,
            $"Expected 3 items. Raw=[{parsed.RawFrontmatter}] Fields.capabilities=[{parsed.GetField("capabilities")}] Got=[{string.Join(",", caps)}]");
        Assert.Contains("read-filesystem", caps);
        Assert.Contains("read-docker-socket", caps);
        Assert.Contains("network", caps);
    }

    [Fact]
    public void FrontmatterParser_MissingField_ReturnsEmptyList()
    {
        var content = "---\nname: test\n---\nbody";
        var parsed = FrontmatterParser.Parse(content);
        var caps = parsed.GetListField("capabilities");

        Assert.Empty(caps);
    }
}
