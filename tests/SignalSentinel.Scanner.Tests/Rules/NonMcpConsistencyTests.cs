using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SignalSentinel.Core;
using SignalSentinel.Core.McpProtocol;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

/// <summary>
/// v2.3.0 fix #21: when SS-INFO-001 fires on a server, MCP-protocol rules for
/// the same server are dropped. The scanner text promises this explicitly
/// ("MCP-protocol rules ... cannot evaluate and were skipped for this target")
/// and v2.3.0 now delivers it.
/// </summary>
public class NonMcpConsistencyTests
{
    private sealed class StubMcpRule : IRule
    {
        private readonly string _ruleId;
        private readonly string _serverName;
        public StubMcpRule(string ruleId, string serverName)
        {
            _ruleId = ruleId;
            _serverName = serverName;
        }
        public string Id => _ruleId;
        public string Name => "Stub";
        public string OwaspCode => "ASI03";
        public string Description => "test";
        public bool EnabledByDefault => true;
        public IReadOnlyList<string> AstCodes => System.Array.Empty<string>();
        public Task<IEnumerable<Finding>> EvaluateAsync(ScanContext _, System.Threading.CancellationToken __ = default)
        {
            return Task.FromResult<IEnumerable<Finding>>(new[]
            {
                new Finding
                {
                    RuleId = _ruleId,
                    OwaspCode = OwaspCode,
                    Severity = Severity.Medium,
                    Title = _ruleId,
                    Description = "d",
                    Remediation = "r",
                    ServerName = _serverName,
                    Confidence = 0.7
                }
            });
        }
    }

    private static ScanContext MakeContext(string nonMcpServerName)
    {
        return new ScanContext
        {
            Servers = new[]
            {
                new ServerEnumeration
                {
                    ServerConfig = new McpServerConfig { Name = nonMcpServerName, Transport = McpTransportType.Http, Url = "https://" + nonMcpServerName },
                    ServerName = nonMcpServerName,
                    Transport = "Http",
                    ConnectionSuccessful = false,
                    NonMcpEvidence = new NonMcpEndpointEvidence
                    {
                        ContentType = "text/html",
                        BodySnippet = "<html/>",
                        Reason = "response body is HTML"
                    }
                }
            }
        };
    }

    [Fact]
    public async Task McpRuleOnNonMcpServer_IsFilteredOut()
    {
        // Arrange: RuleEngine already ships NonMcpEndpointRule in its default set;
        // we add stub MCP rules via customRules to simulate SS-020 et al firing.
        var engine = new RuleEngine(customRules: new IRule[]
        {
            new StubMcpRule(RuleConstants.Rules.OAuthCompliance, "openclaw-vucp"),
            new StubMcpRule(RuleConstants.Rules.MissingAuthentication, "openclaw-vucp"),
            new StubMcpRule(RuleConstants.Rules.ExcessiveToolResponse, "openclaw-vucp")
        });
        var context = MakeContext("openclaw-vucp");

        // Act
        var result = await engine.ExecuteAsync(context);

        // Assert: SS-INFO-001 remains, all three stub MCP rules are dropped.
        var infoFindings = result.Findings.Where(f => f.RuleId == RuleConstants.Rules.NonMcpEndpoint).ToList();
        Assert.Single(infoFindings);

        Assert.DoesNotContain(result.Findings, f => f.RuleId == RuleConstants.Rules.OAuthCompliance);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == RuleConstants.Rules.MissingAuthentication);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == RuleConstants.Rules.ExcessiveToolResponse);
        Assert.True(result.NonMcpFindingsDropped >= 3,
            $"Expected at least 3 dropped findings (stub rules), got {result.NonMcpFindingsDropped}");
    }

    [Fact]
    public async Task McpRuleOnDifferentServer_IsNotFiltered()
    {
        // Non-MCP status on serverA must not suppress findings on serverB.
        var engine = new RuleEngine(customRules: new IRule[]
        {
            new StubMcpRule(RuleConstants.Rules.OAuthCompliance, "other-server")
        });
        var context = MakeContext("openclaw-vucp");

        var result = await engine.ExecuteAsync(context);

        Assert.Contains(result.Findings, f => f.RuleId == RuleConstants.Rules.OAuthCompliance && f.ServerName == "other-server");
    }

    [Fact]
    public async Task SkillRules_AreNotFiltered_EvenWhenSsInfoFires()
    {
        // Skill-surface rules (SS-011..SS-018, SS-024) must continue evaluating
        // even when SS-INFO-001 fires - the SS-INFO-001 text only promises to
        // skip MCP-protocol rules.
        var engine = new RuleEngine(customRules: new IRule[]
        {
            new StubMcpRule(RuleConstants.Rules.SkillInjection, "openclaw-vucp"),
            new StubMcpRule(RuleConstants.Rules.SkillScopeViolation, "openclaw-vucp")
        });
        var context = MakeContext("openclaw-vucp");

        var result = await engine.ExecuteAsync(context);

        Assert.Contains(result.Findings, f => f.RuleId == RuleConstants.Rules.SkillInjection);
        Assert.Contains(result.Findings, f => f.RuleId == RuleConstants.Rules.SkillScopeViolation);
    }
}
