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
