using System.Diagnostics;
using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.Rules.SkillRules;

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// Executes all security rules against enumerated MCP servers.
/// Thread-safe and supports cancellation.
/// </summary>
public sealed class RuleEngine
{
    private readonly IReadOnlyList<IRule> _rules;
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
            new PackageProvenanceRule()
        };

        if (customRules is not null)
        {
            allRules.AddRange(customRules);
        }

        _rules = allRules.Where(r => r.EnabledByDefault).ToList();
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

        return new RuleEngineResult
        {
            Findings = findings,
            AttackPaths = attackPaths,
            RuleResults = ruleResults,
            TotalRulesExecuted = _rules.Count,
            SuccessfulRules = ruleResults.Count(r => r.Value.Success),
            TotalExecutionTimeMs = ruleResults.Values.Sum(r => r.ExecutionTimeMs)
        };
    }

    private async Task<RuleExecutionResult> ExecuteRuleAsync(
        IRule rule, 
        ScanContext context,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var ruleFindings = await rule.EvaluateAsync(context, cancellationToken);
            var findingsList = ruleFindings.ToList();
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
