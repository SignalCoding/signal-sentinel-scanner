using System.Diagnostics;
using SignalSentinel.Core;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules.SkillRules;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// Executes all security rules against enumerated MCP servers.
/// Thread-safe and supports cancellation.
/// </summary>
public sealed class RuleEngine
{
    private readonly List<IRule> _rules;
    private readonly bool _verbose;
    private readonly Action<string>? _logger;

    /// <summary>
    /// Initialises a new instance of the rule engine.
    /// </summary>
    /// <param name="customRules">Optional custom rules to include.</param>
    /// <param name="verbose">Enable verbose logging.</param>
    /// <param name="logger">Logger action for verbose output.</param>
    public RuleEngine(
        IEnumerable<IRule>? customRules = null,
        bool verbose = false,
        Action<string>? logger = null)
    {
        _verbose = verbose;
        _logger = logger;

        var allRules = new List<IRule>
        {
            // MCP Rules (SS-001 to SS-010)
            new ToolPoisoningRule(),
            new OverbroadPermissionsRule(),
            new MissingAuthRule(),
            new SupplyChainRule(),
            new CodeExecutionRule(),
            new MemoryWriteRule(),
            new InterAgentProxyRule(),
            new SensitiveDataRule(),
            new ExcessiveDescriptionRule(),
            new CrossServerAttackPathRule(),

            // Skill Rules (SS-011 to SS-018)
            new SkillInjectionRule(),
            new SkillScopeViolationRule(),
            new SkillCredentialAccessRule(),
            new SkillExfiltrationRule(),
            new SkillObfuscationRule(),
            new SkillScriptPayloadRule(),
            new SkillExcessivePermRule(),
            new SkillHiddenContentRule(),

            // New MCP Rules (SS-019 to SS-021)
            new CredentialHygieneRule(),
            new OAuthComplianceRule(),
            new PackageProvenanceRule(),

            // v2.3.0 informational
            new NonMcpEndpointRule(),

            // v2.4.0 rules
            new NonPublicTargetRule(),          // SS-INFO-002 (A1 / A4)
            new MissingAuthProbeRule(),         // behavioural SS-020 (A2)
            new InstructionalDescriptionRule(), // SS-026 (N5), also covers skills (G6)

            // v2.4.1 rules
            new UntrustedCertificateRule(),      // SS-INFO-003 (G3)
            new SkillIdentityFileWriteRule(),    // SS-028 (G12b)

            // v2.5.0 rules
            new LegacyMcpProtocolRule(),          // SS-INFO-004 (G13a)
            new SkillUnpinnedDependencyRule(),    // SS-029 (G14, SkillJacking)
        };

        if (customRules is not null)
        {
            allRules.AddRange(customRules);
        }

        _rules = [.. allRules.Where(r => r.EnabledByDefault)];
    }

    /// <summary>
    /// Gets all registered rules.
    /// </summary>
    public IReadOnlyList<IRule> Rules => _rules;

    /// <summary>
    /// Executes all rules against the scan context.
    /// </summary>
    /// <param name="context">The scan context containing server data.</param>
    /// <param name="cancellationToken">Token to cancel execution.</param>
    /// <returns>Aggregated results from all rules.</returns>
    public async Task<RuleEngineResult> ExecuteAsync(
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>();
        var attackPaths = new List<AttackPath>();
        var ruleResults = new Dictionary<string, RuleExecutionResult>();

        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();

            Log($"Executing rule: {rule.Id} - {rule.Name}");

            var result = await ExecuteRuleAsync(rule, context, cancellationToken);
            ruleResults[rule.Id] = result;

            if (result.Success && result.Findings is not null)
            {
                findings.AddRange(result.Findings);

                if (rule is CrossServerAttackPathRule attackPathRule)
                {
                    attackPaths.AddRange(attackPathRule.DetectedAttackPaths);
                }

                Log($"  Found {result.FindingsCount} findings in {result.ExecutionTimeMs}ms");
            }
            else if (!result.Success)
            {
                Log($"  Error: {result.Error}");
            }
        }

        // v2.3.0 fix #21: when SS-INFO-001 fires on a server, drop MCP-protocol
        // findings for that same server. The target is demonstrably not an MCP
        // endpoint so MCP rules cannot meaningfully evaluate - firing them anyway
        // would contradict the SS-INFO-001 finding text.
        var nonMcpServers = findings
            .Where(f => string.Equals(f.RuleId, RuleConstants.Rules.NonMcpEndpoint, StringComparison.Ordinal))
            .Select(f => f.ServerName)
            .Where(s => !string.IsNullOrEmpty(s))
            .ToHashSet(StringComparer.Ordinal);

        int droppedCount = 0;
        if (nonMcpServers.Count > 0)
        {
            var filtered = new List<Finding>(findings.Count);
            foreach (var f in findings)
            {
                if (nonMcpServers.Contains(f.ServerName)
                    && RuleConstants.Rules.McpProtocolRules.Contains(f.RuleId))
                {
                    droppedCount++;
                    Log($"  Dropping {f.RuleId} on {f.ServerName}: SS-INFO-001 already fired (non-MCP endpoint)");
                    continue;
                }
                filtered.Add(f);
            }
            findings = filtered;

            // Keep per-rule counts in sync with the filtered findings list so the
            // rule-results dictionary doesn't mislead downstream reporters.
            foreach (var ruleId in RuleConstants.Rules.McpProtocolRules)
            {
                if (!ruleResults.TryGetValue(ruleId, out var r) || r.Findings is null)
                {
                    continue;
                }
                var surviving = r.Findings
                    .Where(f => !nonMcpServers.Contains(f.ServerName))
                    .ToList();
                if (surviving.Count != r.Findings.Count)
                {
                    ruleResults[ruleId] = r with
                    {
                        Findings = surviving,
                        FindingsCount = surviving.Count
                    };
                }
            }
        }

        return new RuleEngineResult
        {
            Findings = findings,
            AttackPaths = attackPaths,
            RuleResults = ruleResults,
            TotalRulesExecuted = _rules.Count,
            SuccessfulRules = ruleResults.Count(r => r.Value.Success),
            TotalExecutionTimeMs = ruleResults.Values.Sum(r => r.ExecutionTimeMs),
            NonMcpFindingsDropped = droppedCount
        };
    }

    private static async Task<RuleExecutionResult> ExecuteRuleAsync(
        IRule rule,
        ScanContext context,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var ruleFindings = await rule.EvaluateAsync(context, cancellationToken);

            var findingsList = ruleFindings
                .Select(f => EnrichFinding(f, context))
                .ToList();
            stopwatch.Stop();

            return new RuleExecutionResult
            {
                RuleId = rule.Id,
                RuleName = rule.Name,
                FindingsCount = findingsList.Count,
                Findings = findingsList,
                ExecutionTimeMs = stopwatch.ElapsedMilliseconds,
                Success = true
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new RuleExecutionResult
            {
                RuleId = rule.Id,
                RuleName = rule.Name,
                FindingsCount = 0,
                ExecutionTimeMs = stopwatch.ElapsedMilliseconds,
                Success = false,
                Error = SanitiseErrorMessage(ex.Message)
            };
        }
    }

    /// <summary>
    /// v2.3.0: enriches a finding with OWASP AST codes from the central mapping when
    /// the rule did not set them explicitly (e.g. SS-012 sets its own).
    /// v2.4.1 (G11): also stamps <see cref="Finding.CanonicalSkillName"/> for
    /// skill-sourced findings, looked up from <see cref="ScanContext.Skills"/> by
    /// ordinal-case-insensitive name match against <see cref="Finding.ServerName"/>
    /// (which doubles as "skill name" for skill findings). Falls back to
    /// <see cref="Finding.ServerName"/> itself when no matching skill definition is
    /// found in context (e.g. in unit tests that construct findings directly).
    /// </summary>
    private static Finding EnrichFinding(Finding finding, ScanContext context)
    {
        var astCodes = finding.AstCodes.Count > 0
            ? finding.AstCodes
            : RuleAstMapping.GetCodes(finding.RuleId);

        var canonicalSkillName = finding.CanonicalSkillName;
        if (finding.Source == FindingSource.Skill && canonicalSkillName is null)
        {
            var skill = context.Skills.FirstOrDefault(s =>
                string.Equals(s.Name, finding.ServerName, StringComparison.OrdinalIgnoreCase));
            canonicalSkillName = skill?.CanonicalSkillName ?? finding.ServerName;
        }

        if (ReferenceEquals(astCodes, finding.AstCodes) &&
            string.Equals(canonicalSkillName, finding.CanonicalSkillName, StringComparison.Ordinal))
        {
            return finding;
        }

        return finding with { AstCodes = astCodes, CanonicalSkillName = canonicalSkillName };
    }

    private static string SanitiseErrorMessage(string message)
    {
        if (message.Length > 200)
        {
            return message[..200] + "...";
        }
        return message;
    }

    private void Log(string message)
    {
        if (_verbose)
        {
            _logger?.Invoke(message);
        }
    }
}

/// <summary>
/// Result from the rule engine execution.
/// </summary>
public sealed record RuleEngineResult
{
    /// <summary>
    /// All findings from all rules.
    /// </summary>
    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>
    /// Attack paths detected by cross-server analysis.
    /// </summary>
    public required IReadOnlyList<AttackPath> AttackPaths { get; init; }

    /// <summary>
    /// Individual results per rule.
    /// </summary>
    public required IReadOnlyDictionary<string, RuleExecutionResult> RuleResults { get; init; }

    /// <summary>
    /// Total number of rules executed.
    /// </summary>
    public int TotalRulesExecuted { get; init; }

    /// <summary>
    /// Number of rules that executed successfully.
    /// </summary>
    public int SuccessfulRules { get; init; }

    /// <summary>
    /// Total execution time across all rules.
    /// </summary>
    public long TotalExecutionTimeMs { get; init; }

    /// <summary>
    /// v2.3.0: number of findings filtered out because SS-INFO-001 fired on the
    /// same target (non-MCP endpoint). Emitted for diagnostics only.
    /// </summary>
    public int NonMcpFindingsDropped { get; init; }
}

/// <summary>
/// Result of executing a single rule.
/// </summary>
public sealed record RuleExecutionResult
{
    /// <summary>
    /// Rule identifier.
    /// </summary>
    public required string RuleId { get; init; }

    /// <summary>
    /// Human-readable rule name.
    /// </summary>
    public required string RuleName { get; init; }

    /// <summary>
    /// Number of findings generated.
    /// </summary>
    public required int FindingsCount { get; init; }

    /// <summary>
    /// The findings (if successful).
    /// </summary>
    public IReadOnlyList<Finding>? Findings { get; init; }

    /// <summary>
    /// Execution time in milliseconds.
    /// </summary>
    public required long ExecutionTimeMs { get; init; }

    /// <summary>
    /// Whether the rule executed successfully.
    /// </summary>
    public required bool Success { get; init; }

    /// <summary>
    /// Error message if execution failed.
    /// </summary>
    public string? Error { get; init; }
}
