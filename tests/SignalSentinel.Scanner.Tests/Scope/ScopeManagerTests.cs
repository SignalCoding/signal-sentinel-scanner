// -----------------------------------------------------------------------
// <copyright file="ScopeManagerTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

using Shouldly;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Scope;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Scope;

public class ScopeManagerTests
{
    private static Finding MakeFinding(string server, FindingSource source = FindingSource.Skill, string? canonicalSkillName = null) =>
        new()
        {
            RuleId = "SS-011",
            OwaspCode = "ASI01",
            Severity = Severity.High,
            Title = "t",
            Description = "d",
            Remediation = "r",
            ServerName = server,
            Source = source,
            CanonicalSkillName = canonicalSkillName
        };

    [Fact]
    public void Matches_EmptyIncludeEmptyExclude_AllIn()
    {
        var sel = new ScopeSelector();
        ScopeManager.Matches(sel, "any").ShouldBeTrue();
    }

    [Fact]
    public void Matches_IncludeOnly_OnlyListedAreIn()
    {
        var sel = new ScopeSelector { Include = ["a", "b"] };
        ScopeManager.Matches(sel, "a").ShouldBeTrue();
        ScopeManager.Matches(sel, "b").ShouldBeTrue();
        ScopeManager.Matches(sel, "c").ShouldBeFalse();
    }

    [Fact]
    public void Matches_ExcludeOnly_ListedAreOut()
    {
        var sel = new ScopeSelector { Exclude = ["bad"] };
        ScopeManager.Matches(sel, "good").ShouldBeTrue();
        ScopeManager.Matches(sel, "bad").ShouldBeFalse();
    }

    [Fact]
    public void Matches_ExcludeWinsOverInclude()
    {
        var sel = new ScopeSelector { Include = ["a"], Exclude = ["a"] };
        ScopeManager.Matches(sel, "a").ShouldBeFalse();
    }

    [Fact]
    public void Matches_IsCaseInsensitive()
    {
        var sel = new ScopeSelector { Include = ["Alpha"] };
        ScopeManager.Matches(sel, "alpha").ShouldBeTrue();
        ScopeManager.Matches(sel, "ALPHA").ShouldBeTrue();
    }

    [Fact]
    public void Apply_NoScope_ReturnsUnmodified()
    {
        var findings = new List<Finding> { MakeFinding("x") };
        var result = ScopeManager.Apply(findings, null);
        result.ShouldBe(findings);
    }

    [Fact]
    public void Apply_WithScope_TagsDormantAndInScope()
    {
        var findings = new List<Finding>
        {
            MakeFinding("kept"),
            MakeFinding("dropped")
        };
        var scope = new SentinelScopeFile
        {
            Skills = new ScopeSelector { Include = ["kept"] }
        };

        var result = ScopeManager.Apply(findings, scope);

        result.Count.ShouldBe(2);
        result[0].Scope.ShouldBe(ScopeManager.InScopeTag);
        result[1].Scope.ShouldBe(ScopeManager.DormantTag);
    }

    [Fact]
    public void Apply_NeverDropsFindings()
    {
        // Dormant findings remain in the list for audit trail; grading ignores them,
        // reports display them in a dedicated section.
        var findings = new List<Finding> { MakeFinding("a"), MakeFinding("b"), MakeFinding("c") };
        var scope = new SentinelScopeFile
        {
            Skills = new ScopeSelector { Include = ["nothing-matches"] }
        };

        var result = ScopeManager.Apply(findings, scope);

        result.Count.ShouldBe(3);
        result.ShouldAllBe(f => f.Scope == ScopeManager.DormantTag);
    }

    [Fact]
    public void Apply_SkillsScopeIgnoresServerFindings()
    {
        var findings = new List<Finding>
        {
            MakeFinding("skill-a", FindingSource.Skill),
            MakeFinding("mcp-server", FindingSource.Mcp)
        };
        var scope = new SentinelScopeFile
        {
            Skills = new ScopeSelector { Include = ["other"] }
        };

        var result = ScopeManager.Apply(findings, scope);

        // Skill out of scope -> dormant; MCP untouched because servers selector is null
        result[0].Scope.ShouldBe(ScopeManager.DormantTag);
        result[1].Scope.ShouldBe(ScopeManager.InScopeTag);
    }

    [Fact]
    public void Apply_SkillsScopeMatchesOnCanonicalNameNotRawServerName()
    {
        // v2.4.1 (G11): scope selectors are authored against the frontmatter-declared
        // skill name; the raw ServerName may be a directory slug that differs from it.
        var findings = new List<Finding>
        {
            MakeFinding("pdf-tools-dir-slug", canonicalSkillName: "pdf-tools")
        };
        var scope = new SentinelScopeFile
        {
            Skills = new ScopeSelector { Include = ["pdf-tools"] }
        };

        var result = ScopeManager.Apply(findings, scope);

        result[0].Scope.ShouldBe(ScopeManager.InScopeTag);
    }

    [Fact]
    public void FromCliFlags_NoFlags_ReturnsNull()
    {
        ScopeManager.FromCliFlags(null, null, null, null).ShouldBeNull();
    }

    [Fact]
    public void FromCliFlags_OnlySkillInclude_BuildsSelector()
    {
        var result = ScopeManager.FromCliFlags(["a", "b"], null, null, null);
        result.ShouldNotBeNull();
        result!.Skills!.Include.ShouldBe(["a", "b"]);
        result.Servers.ShouldBeNull();
    }

    [Fact]
    public void Merge_CliWinsPerSelector()
    {
        var fileScope = new SentinelScopeFile
        {
            Source = "orchestrator.json",
            Skills = new ScopeSelector { Include = ["from-file"] },
            Servers = new ScopeSelector { Include = ["srv-file"] }
        };
        var cliScope = new SentinelScopeFile
        {
            Source = "cli",
            Skills = new ScopeSelector { Include = ["from-cli"] }
            // servers not supplied -> file wins
        };

        var merged = ScopeManager.Merge(fileScope, cliScope);

        merged!.Skills!.Include.ShouldBe(["from-cli"]);
        merged.Servers!.Include.ShouldBe(["srv-file"]);
        merged.Source!.ShouldContain("cli");
    }

    [Fact]
    public async Task LoadAsync_MissingFile_ReturnsNull()
    {
        var result = await ScopeManager.LoadAsync(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json"));
        result.ShouldBeNull();
    }

    [Fact]
    public async Task LoadAsync_ValidFile_ParsesCorrectly()
    {
        var path = Path.Combine(Path.GetTempPath(), $"scope_{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path,
            """
            {
              "version": "1.0",
              "source": "test",
              "skills": { "include": ["a","b"], "exclude": ["c"] }
            }
            """);
        try
        {
            var result = await ScopeManager.LoadAsync(path);
            result.ShouldNotBeNull();
            result!.Version.ShouldBe("1.0");
            result.Source.ShouldBe("test");
            result.Skills!.Include.ShouldBe(["a", "b"]);
            result.Skills.Exclude.ShouldBe(["c"]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_WrongSchemaVersion_Throws()
    {
        var path = Path.Combine(Path.GetTempPath(), $"scope_{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, """{ "version": "2.0" }""");
        try
        {
            await Should.ThrowAsync<InvalidOperationException>(
                () => ScopeManager.LoadAsync(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
