using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Config;

/// <summary>
/// Configuration for the scanner.
/// </summary>
public sealed record ScanConfig
{
    /// <summary>
    /// Path to MCP configuration file (e.g., claude_desktop_config.json).
    /// </summary>
    public string? ConfigPath { get; init; }

    /// <summary>
    /// Remote MCP server URL to scan.
    /// </summary>
    public string? RemoteUrl { get; init; }

    /// <summary>
    /// Auto-discover MCP configurations from known locations.
    /// </summary>
    public bool AutoDiscover { get; init; }

    /// <summary>
    /// Custom rules file path.
    /// </summary>
    public string? CustomRulesPath { get; init; }

    /// <summary>
    /// Output format (json, markdown, html).
    /// </summary>
    public OutputFormat OutputFormat { get; init; } = OutputFormat.Markdown;

    /// <summary>
    /// Output file path (null for stdout).
    /// </summary>
    public string? OutputPath { get; init; }

    /// <summary>
    /// CI mode - exit with code 1 on critical/high findings.
    /// </summary>
    public bool CiMode { get; init; }

    /// <summary>
    /// Verbose output for debugging.
    /// </summary>
    public bool Verbose { get; init; }

    /// <summary>
    /// Connection timeout in seconds.
    /// </summary>
    public int TimeoutSeconds { get; init; } = 30;

    /// <summary>
    /// Scan Agent Skills. When true without SkillsPath, auto-discovers skill directories.
    /// </summary>
    public bool ScanSkills { get; init; }

    /// <summary>
    /// Optional specific path to a skills directory or SKILL.md file.
    /// </summary>
    public string? SkillsPath { get; init; }

    /// <summary>
    /// Optional baseline file path for rug-pull detection (SS-022) and suppression support.
    /// </summary>
    public string? BaselinePath { get; init; }

    /// <summary>
    /// If true, explicitly regenerate the baseline file from the current scan (after review).
    /// </summary>
    public bool UpdateBaseline { get; init; }

    /// <summary>
    /// If true, enforce offline operation: block any outbound network I/O.
    /// When set, --remote is refused and any attempted HTTP call throws.
    /// </summary>
    public bool Offline { get; init; }

    /// <summary>
    /// Optional path to a directory or file containing Sigma YAML rules to evaluate.
    /// </summary>
    public string? SigmaRulesPath { get; init; }

    // v2.3.0 additions

    /// <summary>
    /// Optional path to a suppression file. Defaults to <c>./.sentinel-suppressions.json</c>
    /// when the file exists and no explicit path is supplied.
    /// </summary>
    public string? SuppressionsPath { get; init; }

    /// <summary>
    /// Comma-separated rule identifiers to ignore for a single run (e.g. "SS-014,SS-022").
    /// Equivalent to an ephemeral suppression entry that carries no justification.
    /// </summary>
    public IReadOnlyList<string> IgnoredRules { get; init; } = [];

    /// <summary>
    /// Severity threshold for CI failure (<c>--fail-on critical|high|medium|low|info</c>).
    /// When null, behaviour is the legacy <see cref="CiMode"/> value (critical OR high).
    /// </summary>
    public Severity? FailOn { get; init; }

    /// <summary>
    /// Minimum confidence (0.0..1.0) a finding must reach to be emitted. Findings below
    /// threshold are filtered silently. A value of 0 (default) emits everything.
    /// </summary>
    public double MinConfidence { get; init; }

    /// <summary>
    /// If true, findings below a 0.75 confidence threshold are demoted to <see cref="Severity.Low"/>
    /// but still emitted. Equivalent to "show me everything, but don't let soft signals break CI".
    /// </summary>
    public bool Triage { get; init; }

    /// <summary>
    /// If true, persist this scan's JSON report under <c>.sentinel/history/&lt;iso8601&gt;.json</c>
    /// to enable <c>sentinel-scan diff</c> between runs.
    /// </summary>
    public bool SaveHistory { get; init; }

    /// <summary>
    /// Optional environment label (e.g. "dev", "staging", "prod"). Surfaces in report headers
    /// and is used to scope suppression entries.
    /// </summary>
    public string Environment { get; init; } = "default";

    /// <summary>
    /// Complementary tools listed in the scope disclosure block (e.g. "Bandit, Gitleaks").
    /// </summary>
    public IReadOnlyList<string> ComplementaryTools { get; init; } =
        ["Bandit", "Gitleaks", "Semgrep", "Enkrypt Skill Sentinel"];

    /// <summary>
    /// If true, print every registered rule (id, name, owasp code, ast codes, severity) and exit 0.
    /// </summary>
    public bool ListRules { get; init; }

    /// <summary>
    /// When set, run in diff mode comparing the supplied baseline JSON scan report against the
    /// current scan. Renders only resolved/new/unchanged buckets plus grade-delta attribution.
    /// </summary>
    public string? DiffBaselinePath { get; init; }

    /// <summary>
    /// When set (used with <see cref="DiffBaselinePath"/>), the "current" side of the diff
    /// reads from this file instead of performing a scan. Required by the <c>diff</c> subcommand.
    /// </summary>
    public string? DiffCurrentPath { get; init; }
}

/// <summary>
/// Output format options.
/// </summary>
public enum OutputFormat
{
    Json,
    Markdown,
    Html,
    Sarif
}
