using FluentAssertions;
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
        result.IsSuspicious.Should().BeTrue();
        result.MatchedLegitimateServer.Should().Be(expected);
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
        result.IsSuspicious.Should().BeFalse();
    }

    [Fact]
    public void TyposquatDetector_DetectsPrefixManipulation()
    {
        // Arrange
        var suspicious = "official-mcp-server-filesystem";

        // Act
        var result = TyposquatDetector.CheckForTyposquat(suspicious);

        // Assert
        result.IsSuspicious.Should().BeTrue();
        result.Reason.Should().Contain("prefix");
    }

    [Fact]
    public void TyposquatDetector_DetectsSuffixManipulation()
    {
        // Arrange
        var suspicious = "mcp-server-filesystem-official";

        // Act
        var result = TyposquatDetector.CheckForTyposquat(suspicious);

        // Assert
        result.IsSuspicious.Should().BeTrue();
        result.Reason.Should().Contain("suffix");
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
        findings.Should().ContainSingle();
        findings[0].Title.Should().Contain("Git URL");
        findings[0].Severity.Should().Be(Severity.Medium);
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
        findings.Should().ContainSingle();
        findings[0].Title.Should().Contain("Unknown Package Scope");
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
        findings.Should().ContainSingle();
        findings[0].Title.Should().Contain("Typosquat");
        findings[0].Severity.Should().Be(Severity.High);
    }
}
