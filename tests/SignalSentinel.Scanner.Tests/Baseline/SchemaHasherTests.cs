using System.Text.Json;
using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Scanner.Baseline;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Baseline;

public class SchemaHasherTests
{
    [Fact]
    public void HashDescription_IdenticalText_ProducesSameHash()
    {
        var a = SchemaHasher.HashDescription("Read a file from disk");
        var b = SchemaHasher.HashDescription("Read a file from disk");

        a.ShouldBe(b);
        a.ShouldStartWith("sha256:");
    }

    [Fact]
    public void HashDescription_DifferentText_ProducesDifferentHash()
    {
        var a = SchemaHasher.HashDescription("Read a file from disk");
        var b = SchemaHasher.HashDescription("Write a file to disk");

        a.ShouldNotBe(b);
    }

    [Fact]
    public void HashDescription_WhitespaceNormalisation_ProducesSameHash()
    {
        var a = SchemaHasher.HashDescription("Read a file   \nfrom disk");
        var b = SchemaHasher.HashDescription("Read a file\r\nfrom disk");

        a.ShouldBe(b);
    }

    [Fact]
    public void HashDescription_NullOrEmpty_ProducesSameStableHash()
    {
        var a = SchemaHasher.HashDescription(null);
        var b = SchemaHasher.HashDescription(string.Empty);

        a.ShouldBe(b);
    }

    [Fact]
    public void HashParameters_Null_ProducesStableHash()
    {
        var a = SchemaHasher.HashParameters(null);
        var b = SchemaHasher.HashParameters(null);

        a.ShouldBe(b);
    }

    [Fact]
    public void HashParameters_SameSchema_ProducesSameHash()
    {
        using var docA = JsonDocument.Parse("""{"type":"object","properties":{"name":{"type":"string"}}}""");
        using var docB = JsonDocument.Parse("""{"type":"object","properties":{"name":{"type":"string"}}}""");

        var a = SchemaHasher.HashParameters(docA.RootElement);
        var b = SchemaHasher.HashParameters(docB.RootElement);

        a.ShouldBe(b);
    }

    [Fact]
    public void HashParameters_DifferentPropertyOrder_ProducesSameHashAfterCanonicalisation()
    {
        using var docA = JsonDocument.Parse("""{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}""");
        using var docB = JsonDocument.Parse("""{"properties":{"name":{"type":"string"}},"required":["name"],"type":"object"}""");

        var a = SchemaHasher.HashParameters(docA.RootElement);
        var b = SchemaHasher.HashParameters(docB.RootElement);

        a.ShouldBe(b);
    }

    [Fact]
    public void HashTool_FullHash_IsStable()
    {
        using var doc = JsonDocument.Parse("""{"type":"object"}""");
        var tool = new McpToolDefinition
        {
            Name = "read_file",
            Description = "Read a file",
            InputSchema = doc.RootElement.Clone()
        };

        var a = SchemaHasher.HashTool(tool);
        var b = SchemaHasher.HashTool(tool);

        a.ShouldBe(b);
    }
}
