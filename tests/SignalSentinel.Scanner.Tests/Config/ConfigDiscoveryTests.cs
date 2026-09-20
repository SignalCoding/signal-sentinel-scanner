using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Scanner.Config;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Config;

public class ConfigDiscoveryTests
{
    private static readonly string Home = Path.GetTempPath();

    [Fact]
    public void UserConfigCandidates_IncludesWp8Applications()
    {
        var candidates = ConfigDiscovery.UserConfigCandidates(Home, Home, Home);

        candidates.ShouldContain(("Claude Code", Path.Combine(Home, ".claude.json")));
        candidates.ShouldContain(("Gemini CLI", Path.Combine(Home, ".gemini", "settings.json")));
        candidates.ShouldContain(("OpenCode", Path.Combine(Home, ".config", "opencode", "opencode.json")));
        candidates.ShouldContain(("VS Code / Copilot", candidates.First(c => c.Application == "VS Code / Copilot").FullPath));
        candidates.ShouldContain(("GitHub Copilot (JetBrains)", Path.Combine(Home, ".config", "github-copilot", "intellij", "mcp.json")));
        candidates.ShouldContain(("Amazon Q Developer", Path.Combine(Home, ".aws", "amazonq", "mcp.json")));
    }

    [Fact]
    public void UserConfigCandidates_KeepsPreExistingEntries()
    {
        var candidates = ConfigDiscovery.UserConfigCandidates(Home, Home, Home);

        candidates.Select(c => c.Application).ShouldContain("Claude Desktop");
        candidates.Select(c => c.Application).ShouldContain("Cursor");
        candidates.Select(c => c.Application).ShouldContain("VS Code");
        candidates.Select(c => c.Application).ShouldContain("Windsurf");
        candidates.Select(c => c.Application).ShouldContain("Zed");
    }

    [Fact]
    public void ProjectConfigCandidates_AreTheSixWp8Locations()
    {
        var candidates = ConfigDiscovery.ProjectConfigCandidates;

        candidates.Select(c => c.RelativePath).ShouldBe(
            [
                ".mcp.json",
                Path.Combine(".gemini", "settings.json"),
                "opencode.json",
                Path.Combine(".vscode", "mcp.json"),
                Path.Combine(".amazonq", "mcp.json"),
                Path.Combine(".cursor", "mcp.json"),
            ],
            ignoreOrder: true);
        candidates.Select(c => c.Application).ShouldAllBe(a => a.EndsWith("(project)", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Parse_McpServersShape_StillWorks()
    {
        await WithTempConfig(
            """{ "mcpServers": { "fs": { "command": "npx", "args": ["-y", "pkg"] } } }""",
            config =>
            {
                config.Servers.Count.ShouldBe(1);
                config.Servers[0].Name.ShouldBe("fs");
                config.Servers[0].Command.ShouldBe("npx");
                config.Servers[0].Args.ShouldBe(["-y", "pkg"]);
            });
    }

    [Fact]
    public async Task Parse_VsCodeServersObject_Parses()
    {
        await WithTempConfig(
            """{ "servers": { "web": { "type": "http", "url": "https://mcp.example.com/mcp" } } }""",
            config =>
            {
                config.Servers.Count.ShouldBe(1);
                config.Servers[0].Name.ShouldBe("web");
                config.Servers[0].Transport.ShouldBe(McpTransportType.Http);
                config.Servers[0].Url.ShouldBe("https://mcp.example.com/mcp");
            });
    }

    [Fact]
    public async Task Parse_ServersArray_StillWorks()
    {
        await WithTempConfig(
            """{ "servers": [ { "name": "arr", "command": "run-it" } ] }""",
            config =>
            {
                config.Servers.Count.ShouldBe(1);
                config.Servers[0].Name.ShouldBe("arr");
                config.Servers[0].Command.ShouldBe("run-it");
            });
    }

    [Fact]
    public async Task Parse_OpenCodeMcpObject_ParsesCommandArrayAndEnvironment()
    {
        const string json = """
            {
              "mcp": {
                "local-one": {
                  "type": "local",
                  "command": ["bun", "x", "the-package", "--flag"],
                  "environment": { "TOKEN": "abc" }
                },
                "remote-one": { "type": "remote", "url": "https://mcp.example.com/x" }
              }
            }
            """;

        await WithTempConfig(json, config =>
        {
            config.Servers.Count.ShouldBe(2);
            var local = config.Servers.Single(s => s.Name == "local-one");
            local.Command.ShouldBe("bun");
            local.Args.ShouldBe(["x", "the-package", "--flag"]);
            local.Env.ShouldNotBeNull().ShouldContainKeyAndValue("TOKEN", "abc");
            local.Transport.ShouldBe(McpTransportType.Stdio);

            var remote = config.Servers.Single(s => s.Name == "remote-one");
            remote.Transport.ShouldBe(McpTransportType.Http);
            remote.Url.ShouldBe("https://mcp.example.com/x");
        });
    }

    [Fact]
    public async Task Parse_OpenCodeDisabledEntry_IsSkipped()
    {
        const string json = """
            { "mcp": { "off": { "type": "local", "enabled": false, "command": ["x"] } } }
            """;

        await WithTempConfig(json, config => config.Servers.ShouldBeEmpty());
    }

    [Fact]
    public void IsPathSafe_SiblingPrefixOfRoot_IsRejected()
    {
        // Regression: "Roaming-evil\x.json" must not pass when the root is "Roaming".
        var root = Path.Combine(Path.GetTempPath(), $"sentinel-root-{Guid.NewGuid():N}");
        var sibling = root + "-evil";

        ConfigDiscovery.IsPathSafe(Path.Combine(root, "mcp.json"), [root]).ShouldBeTrue();
        ConfigDiscovery.IsPathSafe(Path.Combine(sibling, "mcp.json"), [root]).ShouldBeFalse();
        ConfigDiscovery.IsPathSafe(Path.Combine(root, "sub", "mcp.json"), [root]).ShouldBeTrue();
    }

    [Fact]
    public void IsPathSafe_TraversalAndSuspiciousSegments_Rejected()
    {
        var root = Path.GetTempPath();

        ConfigDiscovery.IsPathSafe(Path.Combine(root, "..", "mcp.json"), [root]).ShouldBeFalse();
        ConfigDiscovery.IsPathSafe(null, [root]).ShouldBeFalse();
        ConfigDiscovery.IsPathSafe("  ", [root]).ShouldBeFalse();
    }

    [Fact]
    public async Task Parse_EntryWithNeitherCommandNorUrl_IsDropped()
    {
        await WithTempConfig(
            """{ "mcpServers": { "hollow": { "env": { "A": "1" } }, "real": { "command": "x" } } }""",
            config =>
            {
                config.Servers.Count.ShouldBe(1);
                config.Servers[0].Name.ShouldBe("real");
            });
    }

    [Fact]
    public async Task Parse_OpenCodeRemoteWithoutUrl_IsDropped()
    {
        await WithTempConfig(
            """{ "mcp": { "hollow-remote": { "type": "remote" } } }""",
            config => config.Servers.ShouldBeEmpty());
    }

    [Fact]
    public async Task Parse_EnabledFalseInMcpServers_IsSkipped()
    {
        await WithTempConfig(
            """{ "mcpServers": { "off": { "enabled": false, "command": "x" } } }""",
            config => config.Servers.ShouldBeEmpty());
    }

    [Fact]
    public async Task Parse_PathOutsideUserRoots_ReturnsNull()
    {
        var outside = Path.Combine(Path.GetPathRoot(Path.GetTempPath())!, "definitely-not-a-user-root", "mcp.json");

        var config = await ConfigDiscovery.ParseConfigFileAsync(outside, "Test");

        config.ShouldBeNull();
    }

    private static async Task WithTempConfig(string json, Action<McpConfigFile> assertion)
    {
        var path = Path.Combine(Path.GetTempPath(), $"sentinel-cfg-{Guid.NewGuid():N}.json");
        try
        {
            await File.WriteAllTextAsync(path, json).ConfigureAwait(true);

            // The temp directory is not necessarily under a user-profile root (CI
            // runners), so the test parses against the temp root explicitly.
            var config = await ConfigDiscovery.ParseConfigFileCoreAsync(
                path, "Test", [Path.GetTempPath()]).ConfigureAwait(true);
            config.ShouldNotBeNull();
            assertion(config);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
