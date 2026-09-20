using System;
using System.IO;
using System.Linq;
using Shouldly;
using SignalSentinel.Scanner.SkillParser;
using Xunit;

namespace SignalSentinel.Scanner.Tests.SkillParser;

public class SkillDiscoveryTests
{
    [Fact]
    public void ProjectPaths_IncludesWp8Directories()
    {
        var subPaths = SkillDiscovery.ProjectPaths.Select(p => p.SubPath).ToArray();

        subPaths.ShouldContain(".gemini/skills");
        subPaths.ShouldContain(".opencode/skills");
        subPaths.ShouldContain(".github/skills");
        subPaths.ShouldContain(".factory/skills");
        subPaths.ShouldContain(".agents/skills");
    }

    [Fact]
    public void ProjectPaths_KeepsPreExistingDirectories()
    {
        var subPaths = SkillDiscovery.ProjectPaths.Select(p => p.SubPath).ToArray();

        subPaths.ShouldContain(".claude/skills");
        subPaths.ShouldContain(".codex/skills");
        subPaths.ShouldContain(".cursor/skills");
        subPaths.ShouldContain(".windsurf/skills");
        subPaths.ShouldContain(".agent-skills");
    }

    [Fact]
    public void PluginCacheSkillDirectories_EmptyHome_ReturnsEmpty()
    {
        SkillDiscovery.PluginCacheSkillDirectories(string.Empty).ShouldBeEmpty();
    }

    [Fact]
    public void PluginCacheSkillDirectories_NoPluginsRoot_ReturnsEmpty()
    {
        var home = Path.Combine(Path.GetTempPath(), $"sentinel-home-{Guid.NewGuid():N}");
        Directory.CreateDirectory(home);
        try
        {
            SkillDiscovery.PluginCacheSkillDirectories(home).ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(home, recursive: true);
        }
    }

    [Fact]
    public void PluginCacheSkillDirectories_FindsCacheAndMarketplaceSkills()
    {
        var home = Path.Combine(Path.GetTempPath(), $"sentinel-home-{Guid.NewGuid():N}");
        var cacheSkills = Path.Combine(home, ".claude", "plugins", "cache", "owner", "plugin", "skills");
        var cacheNoSkills = Path.Combine(home, ".claude", "plugins", "cache", "owner", "other-plugin");
        var marketplaceSkills = Path.Combine(home, ".claude", "plugins", "marketplaces", "mp", "nested", "deep", "skills");
        Directory.CreateDirectory(cacheSkills);
        Directory.CreateDirectory(cacheNoSkills);
        Directory.CreateDirectory(marketplaceSkills);

        try
        {
            var found = SkillDiscovery.PluginCacheSkillDirectories(home);

            found.ShouldContain(cacheSkills);
            found.ShouldContain(marketplaceSkills);
            found.ShouldNotContain(cacheNoSkills);
        }
        finally
        {
            Directory.Delete(home, recursive: true);
        }
    }

    [Fact]
    public void PluginCacheSkillDirectories_CacheSkillsAtWrongDepth_NotMatched()
    {
        // cache/<owner>/skills (one level, not two) is not a plugin skills directory.
        var home = Path.Combine(Path.GetTempPath(), $"sentinel-home-{Guid.NewGuid():N}");
        var shallow = Path.Combine(home, ".claude", "plugins", "cache", "owner", "skills");
        Directory.CreateDirectory(shallow);

        try
        {
            SkillDiscovery.PluginCacheSkillDirectories(home).ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(home, recursive: true);
        }
    }
}
