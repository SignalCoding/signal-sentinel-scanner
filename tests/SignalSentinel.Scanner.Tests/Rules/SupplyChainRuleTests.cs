using Shouldly;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Core.Security;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class SupplyChainRuleTests
{
    private readonly SupplyChainRule _rule = new();

    [Theory]
    [InlineData("mcp-server-filesystm", "mcp-server-filesystem")] // Missing 'e'
    [InlineData("mcp-server-filsystem", "mcp-server-filesystem")] // Missing 'e'
    [InlineData("mcp-srver-github", "mcp-server-github")]         // Missing 'e'
    public void TyposquatDetector_DetectsSimilarNames(string suspicious, string expected)
    {
        // Act
        var result = TyposquatDetector.CheckForTyposquat(suspicious);

        // Assert
        result.IsSuspicious.ShouldBeTrue();
        result.MatchedLegitimateServer.ShouldBe(expected);
    }

    [Theory]
    [InlineData("my-custom-server")]
    [InlineData("company-internal-mcp")]
    [InlineData("totally-unique-name")]
    public void TyposquatDetector_AllowsUniqueNames(string serverName)
    {
        // Act
        var result = TyposquatDetector.CheckForTyposquat(serverName);

        // Assert
        result.IsSuspicious.ShouldBeFalse();
    }

    [Fact]
    public void TyposquatDetector_DetectsPrefixManipulation()
    {
        // Arrange
        var suspicious = "official-mcp-server-filesystem";

        // Act
        var result = TyposquatDetector.CheckForTyposquat(suspicious);

        // Assert
        result.IsSuspicious.ShouldBeTrue();
        result.Reason.ShouldContain("prefix");
    }

    [Fact]
    public void TyposquatDetector_DetectsSuffixManipulation()
    {
        // Arrange
        var suspicious = "mcp-server-filesystem-official";

        // Act
        var result = TyposquatDetector.CheckForTyposquat(suspicious);

        // Assert
        result.IsSuspicious.ShouldBeTrue();
        result.Reason.ShouldContain("suffix");
    }

    [Fact]
    public async Task Evaluate_WithGitUrl_ReturnsWarning()
    {
        // Arrange
        var context = new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig
                    {
                        Name = "git-package",
                        Command = "npx",
                        Args = ["git+https://github.com/unknown/mcp-server.git"]
                    },
                    ServerName = "git-package",
                    Transport = "stdio",
                    ConnectionSuccessful = true,
                    Tools = []
                }
            ]
        };

        // Act
        var findings = (await _rule.EvaluateAsync(context)).ToList();

        // Assert
        findings.Count.ShouldBe(1);
        findings[0].Title.ShouldContain("Git URL");
        findings[0].Severity.ShouldBe(Severity.Medium);
    }

    [Fact]
    public async Task Evaluate_WithUnknownScope_ReturnsInfo()
    {
        // Arrange
        var context = new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig
                    {
                        Name = "scoped-package",
                        Command = "npx",
                        Args = ["@random-org/mcp-server"]
                    },
                    ServerName = "scoped-package",
                    Transport = "stdio",
                    ConnectionSuccessful = true,
                    Tools = []
                }
            ]
        };

        // Act
        var findings = (await _rule.EvaluateAsync(context)).ToList();

        // Assert
        findings.Count.ShouldBe(1);
        findings[0].Title.ShouldContain("Unknown Package Scope");
    }

    [Fact]
    public async Task Evaluate_WithTyposquatName_ReturnsHighSeverity()
    {
        // Arrange
        var context = new ScanContext
        {
            Servers =
            [
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig { Name = "mcp-server-filesystm" },
                    ServerName = "mcp-server-filesystm", // Typo of filesystem
                    Transport = "stdio",
                    ConnectionSuccessful = true,
                    Tools = []
                }
            ]
        };

        // Act
        var findings = (await _rule.EvaluateAsync(context)).ToList();

        // Assert
        findings.Count.ShouldBe(1);
        findings[0].Title.ShouldContain("Typosquat");
        findings[0].Severity.ShouldBe(Severity.High);
    }
}
