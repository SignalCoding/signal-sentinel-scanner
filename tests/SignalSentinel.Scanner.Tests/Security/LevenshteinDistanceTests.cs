using Shouldly;
using SignalSentinel.Core.Security;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Security;

public class LevenshteinDistanceTests
{
    [Theory]
    [InlineData("", "", 0)]
    [InlineData("abc", "abc", 0)]
    [InlineData("", "abc", 3)]
    [InlineData("abc", "", 3)]
    [InlineData("abc", "abd", 1)]
    [InlineData("read_file", "read_fil", 1)]
    [InlineData("read_file", "raed_file", 2)]
    [InlineData("kitten", "sitting", 3)]
    public void Compute_KnownValues(string a, string b, int expected)
    {
        LevenshteinDistance.Compute(a, b).ShouldBe(expected);
    }

    [Fact]
    public void Compute_Symmetric()
    {
        var a = LevenshteinDistance.Compute("abc", "xyz");
        var b = LevenshteinDistance.Compute("xyz", "abc");
        a.ShouldBe(b);
    }
}
