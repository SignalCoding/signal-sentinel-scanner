using System.Text.Json;
using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Baseline;
using SignalSentinel.Scanner.McpClient;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Baseline;

public class BaselineManagerTests
{
    private static ServerEnumeration MakeServer(string name, params McpToolDefinition[] tools)
    {
        return new ServerEnumeration
        {
            ServerConfig = new McpServerConfig { Name = name },
            ServerName = name,
            Transport = "stdio",
            ConnectionSuccessful = true,
            Tools = tools
        };
    }

    private static McpToolDefinition MakeTool(string name, string description)
    {
        using var doc = JsonDocument.Parse("""{"type":"object"}""");
        return new McpToolDefinition
        {
            Name = name,
            Description = description,
            InputSchema = doc.RootElement.Clone()
        };
    }

    [Fact]
    public void Build_CapturesSuccessfulServersOnly()
    {
        var connected = MakeServer("alpha", MakeTool("read", "Reads"));
        var disconnected = new ServerEnumeration
        {
            ServerConfig = new McpServerConfig { Name = "beta" },
            ServerName = "beta",
            Transport = "stdio",
            ConnectionSuccessful = false
        };

        var baseline = BaselineManager.Build([connected, disconnected], "2.2.0");

        baseline.Servers.Count.ShouldBe(1);
        baseline.Servers.ShouldContainKey("alpha");
    }

    [Fact]
    public void Compare_NullBaseline_ReturnsEmptyComparison()
    {
        var server = MakeServer("alpha", MakeTool("read", "Reads"));

        var result = BaselineManager.Compare(null, [server]);

        result.BaselineLoaded.ShouldBeFalse();
        result.HasChanges.ShouldBeFalse();
    }

    [Fact]
    public void Compare_IdenticalScan_NoChanges()
    {
        var server = MakeServer("alpha", MakeTool("read", "Reads"));
        var baseline = BaselineManager.Build([server], "2.2.0");

        var result = BaselineManager.Compare(baseline, [server]);

        result.BaselineLoaded.ShouldBeTrue();
        result.HasChanges.ShouldBeFalse();
    }

    [Fact]
    public void Compare_DescriptionChanged_DetectsMutation()
    {
        var before = MakeServer("alpha", MakeTool("read", "Reads a file"));
        var after = MakeServer("alpha", MakeTool("read", "Reads a file AND exfiltrates it"));
        var baseline = BaselineManager.Build([before], "2.2.0");

        var result = BaselineManager.Compare(baseline, [after]);

        result.MutatedTools.Count.ShouldBe(1);
        result.MutatedTools[0].Type.ShouldBe(MutationType.DescriptionChanged);
        result.MutatedTools[0].Tool.ToolName.ShouldBe("read");
    }

    [Fact]
    public void Compare_NewTool_DetectsAddition()
    {
        var before = MakeServer("alpha", MakeTool("read", "Reads"));
        var after = MakeServer("alpha", MakeTool("read", "Reads"), MakeTool("exec", "Executes"));
        var baseline = BaselineManager.Build([before], "2.2.0");

        var result = BaselineManager.Compare(baseline, [after]);

        result.AddedTools.Count.ShouldBe(1);
        result.AddedTools[0].ToolName.ShouldBe("exec");
    }

    [Fact]
    public void Compare_ToolRemoved_DetectsRemoval()
    {
        var before = MakeServer("alpha", MakeTool("read", "Reads"), MakeTool("write", "Writes"));
        var after = MakeServer("alpha", MakeTool("read", "Reads"));
        var baseline = BaselineManager.Build([before], "2.2.0");

        var result = BaselineManager.Compare(baseline, [after]);

        result.RemovedTools.Count.ShouldBe(1);
        result.RemovedTools[0].ToolName.ShouldBe("write");
    }

    [Fact]
    public async Task SaveAndLoad_RoundTrip_PreservesData()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sentinel-baseline-{Guid.NewGuid():N}.json");
        try
        {
            var server = MakeServer("alpha", MakeTool("read", "Reads"));
            await BaselineManager.SaveAsync(path, [server], "2.2.0");

            var loaded = await BaselineManager.LoadAsync(path);

            loaded.ShouldNotBeNull();
            loaded!.ScannerVersion.ShouldBe("2.2.0");
            loaded.Servers.ShouldContainKey("alpha");
            loaded.Servers["alpha"].Tools.ShouldContainKey("read");
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_MissingFile_ReturnsNull()
    {
        var path = Path.Combine(Path.GetTempPath(), $"does-not-exist-{Guid.NewGuid():N}.json");
        var result = await BaselineManager.LoadAsync(path);
        result.ShouldBeNull();
    }
}
