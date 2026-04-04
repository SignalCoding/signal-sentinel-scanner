using SignalSentinel.Core.Models;
using SignalSentinel.Scanner.McpClient;

#pragma warning disable CA1002 // Justification: ScanContext is an internal model, not a public API surface

namespace SignalSentinel.Scanner.Rules;

/// <summary>
/// Interface for security rules that evaluate MCP server configurations.
/// All rules should be stateless and thread-safe.
/// </summary>
public interface IRule
{
    /// <summary>
    /// Unique rule identifier following the SS-XXX pattern (e.g., "SS-001").
    /// </summary>
    string Id { get; }

    /// <summary>
    /// Human-readable rule name for display in reports.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// OWASP Agentic AI Security code (e.g., "ASI01").
    /// Maps this rule to the OWASP ASI Top 10 risk categories.
    /// </summary>
    string OwaspCode { get; }

    /// <summary>
    /// Detailed rule description explaining what the rule detects.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Whether this rule is enabled by default in standard scans.
    /// </summary>
    bool EnabledByDefault { get; }

    /// <summary>
    /// Evaluates the rule against enumerated server data.
    /// </summary>
    /// <param name="context">Scan context containing all enumerated servers.</param>
    /// <param name="cancellationToken">Token to cancel the evaluation.</param>
    /// <returns>List of findings from this rule.</returns>
    Task<IEnumerable<Finding>> EvaluateAsync(
        ScanContext context, 
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Context provided to rules during evaluation.
/// Immutable record containing all data needed for rule evaluation.
/// </summary>
public sealed record ScanContext
{
    /// <summary>
    /// All enumerated MCP servers and their tools/resources/prompts.
    /// </summary>
    public required IReadOnlyList<ServerEnumeration> Servers { get; init; }

    /// <summary>
    /// All parsed Agent Skills (empty when skill scanning is not performed).
    /// </summary>
    public IReadOnlyList<SkillDefinition> Skills { get; init; } = [];

    /// <summary>
    /// Previous scan results for comparison (enables drift detection).
    /// </summary>
    public ScanResult? PreviousScan { get; init; }

    /// <summary>
    /// Optional policy configuration for rule customisation.
    /// </summary>
    public PolicyConfiguration? Policy { get; init; }
}

/// <summary>
/// Policy configuration for customising rule behaviour.
/// </summary>
public sealed record PolicyConfiguration
{
    /// <summary>
    /// Servers to exclude from scanning.
    /// </summary>
    public IReadOnlyList<string> ExcludedServers { get; init; } = [];

    /// <summary>
    /// Tools to exclude from scanning.
    /// </summary>
    public IReadOnlyList<string> ExcludedTools { get; init; } = [];

    /// <summary>
    /// Custom severity overrides by rule ID.
    /// </summary>
    public IReadOnlyDictionary<string, Severity> SeverityOverrides { get; init; } = 
        new Dictionary<string, Severity>();
}
