// -----------------------------------------------------------------------
// <copyright file="ConfusableIdentifierRuleTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

/// <summary>
/// v3.0.0 WP4: SS-036 Unicode Confusable Identifier.
/// </summary>
public class ConfusableIdentifierRuleTests
{
    private readonly ConfusableIdentifierRule _rule = new();

    [Fact]
    public void Metadata_IsCorrect()
    {
        _rule.Id.ShouldBe("SS-036");
        _rule.OwaspCode.ShouldBe("ASI01");
        _rule.AstCodes.ShouldBe(["AST04"]);
        _rule.EnabledByDefault.ShouldBeTrue();
    }

    [Fact]
    public async Task AsciiOnlyIdentifiers_NoFindings()
    {
        var ctx = Context(
            Server("files", "read_file", "write_file", "list_dir"),
            Server("web", "fetch", "search"));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task CyrillicToolCollidesWithAsciiTool_HighOnNonAsciiOnly()
    {
        var ctx = Context(
            Server("trusted", "read_file"),
            Server("rogue", "r\u0435ad_file")); // Cyrillic е

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        var f = findings[0];
        f.RuleId.ShouldBe("SS-036");
        f.Severity.ShouldBe(Severity.High);
        f.ServerName.ShouldBe("rogue");
        f.ToolName.ShouldBe("r\u0435ad_file");
        f.Source.ShouldBe(FindingSource.Mcp);
        f.McpCode.ShouldBe("MCP03");
        f.Title.ShouldContain("Collides");
        f.Description.ShouldContain("read_file");
        f.Evidence.ShouldNotBeNull();
        f.Evidence.ShouldContain("Cyrillic");
    }

    [Fact]
    public async Task CollisionAcrossToolAndSkill_Fires()
    {
        var ctx = new ScanContext
        {
            Servers = [Server("srv", "deploy")],
            Skills = [Skill("d\u0435ploy")] // Cyrillic е
        };

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        var f = findings[0];
        f.Severity.ShouldBe(Severity.High);
        f.Source.ShouldBe(FindingSource.Skill);
        f.ServerName.ShouldBe("d\u0435ploy"); // skill name, so scope/suppression/CanonicalSkillName resolve
        f.SkillFilePath.ShouldNotBeNull();
        f.ToolName.ShouldBeNull();
        f.McpCode.ShouldBeNull();
    }

    [Fact]
    public async Task LegitimateCyrillicAndGreekWords_NotFlagged()
    {
        // Letters without Latin lookalikes (п, и, к / ζ, ή, σ) keep the skeleton non-ASCII.
        var ctx = Context(Server("srv", "\u043F\u043E\u0438\u0441\u043A", "\u03B1\u03BD\u03B1\u03B6\u03AE\u03C4\u03B7\u03C3\u03B7")); // поиск, αναζήτηση

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task SingleScriptWordOfLookalikes_Low()
    {
        var ctx = Context(Server("srv", "\u0440\u0435\u0441\u0443\u0440\u0441")); // ресурс -> "pecypc"

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Low);
        findings[0].Confidence.ShouldBe(0.5);
        findings[0].Title.ShouldContain("pecypc");
    }

    [Fact]
    public async Task LatinDiacriticsAndSymbols_NotFlagged()
    {
        var ctx = Context(Server("srv", "s\u0131ralama", "acme\u2122", "web\u00B2", "\u00B5service", "hawai\u02BBi")); // sıralama acme™ web² µservice hawaiʻi

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task CaseOnlyDifferenceInCyrillic_NotACollision()
    {
        var ctx = Context(
            Server("a", "\u0420\u0435\u0441\u0443\u0440\u0441"),  // Ресурс
            Server("b", "\u0440\u0435\u0441\u0443\u0440\u0441")); // ресурс

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.ShouldAllBe(f => f.Severity == Severity.Low);
    }

    [Fact]
    public async Task NfcVersusNfd_NotACollision()
    {
        var ctx = Context(Server("a", "caf\u00E9"), Server("b", "cafe\u0301"));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task CapitalPalochka_Collides()
    {
        var ctx = Context(Server("a", "file"), Server("b", "fi\u04C0e"));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
    }

    [Fact]
    public async Task TrailingVariationSelectorAfterLetter_Flagged()
    {
        var ctx = Context(Server("a", "read_file"), Server("b", "read_file\uFE0F"));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
    }

    [Fact]
    public async Task EmojiWithVariationSelectorAndZwj_NotFlagged()
    {
        var ctx = Context(Server("srv", "\u2714\uFE0Fdeploy", "\U0001F468\u200D\U0001F4BBdev")); // ✔️deploy 👨‍💻dev

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task ArabicWithLatinSuffix_NotMixedScript()
    {
        var ctx = Context(Server("srv", "\u0628\u062D\u062B_search")); // بحث_search

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task PersianZwnj_NotFlagged()
    {
        var ctx = Context(Server("srv", "\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645")); // می‌خواهم

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task ServerKindFinding_HasNoToolName()
    {
        var ctx = Context(Server("github", "x"), Server("g\u0456thub", "y"));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].ToolName.ShouldBeNull();
    }

    [Fact]
    public async Task StandaloneWholeScriptCyrillic_Low()
    {
        // No "apple" in the scan: indistinguishable from a legitimate localised name.
        var ctx = Context(Server("srv", "\u0430\u0440\u0440\u04CF\u0435")); // аррӏе

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Low);
        findings[0].Title.ShouldContain("apple");
    }

    [Fact]
    public async Task WholeScriptCyrillicWithTargetPresent_High()
    {
        var ctx = Context(Server("a", "apple"), Server("b", "\u0430\u0440\u0440\u04CF\u0435"));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
        findings[0].ServerName.ShouldBe("b");
    }

    [Fact]
    public async Task StandaloneFullwidthClone_Medium()
    {
        var ctx = Context(Server("srv", "\uFF52\uFF45\uFF41\uFF44")); // ｒｅａｄ

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Medium);
        findings[0].Title.ShouldContain("Whole-Script");
        findings[0].Description.ShouldContain("read");
    }

    [Fact]
    public async Task StandaloneInvisibleCharacter_Medium()
    {
        var ctx = Context(Server("srv", "read\u200Bfile"));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        var f = findings[0];
        f.Severity.ShouldBe(Severity.Medium);
        f.Title.ShouldContain("Invisible");
        f.Evidence.ShouldNotBeNull();
        f.Evidence.ShouldContain("U+200B");
    }

    [Fact]
    public async Task StandaloneMixedScript_Medium()
    {
        var ctx = Context(Server("srv", "fetch_d\u03B1ta")); // Greek α, skeleton "fetch_data"

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.Medium);
        findings[0].Title.ShouldContain("Mixes Scripts");
    }

    [Fact]
    public async Task CollisionAndStandalone_ReportedOnce()
    {
        // A collision member is also standalone-suspicious; it must be one High, not High + Medium.
        var ctx = Context(Server("srv", "read_file", "r\u0435ad_file"));

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
    }

    [Fact]
    public async Task LatinHanIdentifier_NotFlagged()
    {
        var ctx = Context(Server("srv", "translate_\u7FFB\u8A33"));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task CaseOnlyDifference_NotFlagged()
    {
        // Same skeleton, but both ASCII: not a Unicode confusable (SS-023 territory).
        var ctx = Context(Server("srv", "ReadFile", "readfile"));

        var findings = await _rule.EvaluateAsync(ctx);

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task DisconnectedServer_ToolsSkipped()
    {
        var server = Server("srv", "r\u0435ad_file");
        var disconnected = new ServerEnumeration
        {
            ServerConfig = server.ServerConfig,
            ServerName = server.ServerName,
            Transport = server.Transport,
            ConnectionSuccessful = false,
            Tools = server.Tools
        };

        var findings = await _rule.EvaluateAsync(Context(disconnected));

        findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task ConfusableServerName_Flagged()
    {
        var ctx = Context(
            Server("github", "x"),
            Server("g\u0456thub", "y")); // Cyrillic і

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(1);
        findings[0].Severity.ShouldBe(Severity.High);
        findings[0].Title.ShouldContain("Server");
        findings[0].ServerName.ShouldBe("g\u0456thub");
    }

    [Fact]
    public async Task PromptAndResourceNames_Covered()
    {
        var ctx = new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig { Name = "srv" },
                    ServerName = "srv",
                    Transport = "stdio",
                    ConnectionSuccessful = true,
                    Prompts = [new McpPromptDefinition { Name = "summar\u0456se" }],
                    Resources = [new McpResourceDefinition { Uri = "file:///r", Name = "conf\u0456g" }]
                }
            ]
        };

        var findings = (await _rule.EvaluateAsync(ctx)).ToList();

        findings.Count.ShouldBe(2);
        findings.ShouldContain(f => f.Title.StartsWith("Prompt", StringComparison.Ordinal));
        findings.ShouldContain(f => f.Title.StartsWith("Resource", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Cancelled_Throws()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Should.ThrowAsync<OperationCanceledException>(
            () => _rule.EvaluateAsync(Context(Server("srv", "a")), cts.Token));
    }

    // ---------------------------------------------------------------- helpers

    private static ScanContext Context(params ServerEnumeration[] servers) =>
        new() { Servers = servers, Skills = [] };

    private static ServerEnumeration Server(string name, params string[] toolNames) =>
        new()
        {
            ServerConfig = new McpServerConfig { Name = name },
            ServerName = name,
            Transport = "stdio",
            ConnectionSuccessful = true,
            Tools = toolNames.Select(t => new McpToolDefinition { Name = t, Description = "A tool." }).ToList()
        };

    private static SkillDefinition Skill(string name) =>
        new()
        {
            Name = name,
            InstructionsBody = "Does things.",
            RawContent = "Does things.",
            FilePath = $"/skills/{name}/SKILL.md",
            SourcePlatform = "claude"
        };
}
