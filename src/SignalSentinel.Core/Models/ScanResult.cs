namespace SignalSentinel.Core.Models;

/// <summary>
/// Complete scan result for one or more MCP servers.
/// </summary>
public sealed record ScanResult
{
    /// <summary>
    /// Timestamp when the scan was performed (UTC).
    /// </summary>
    public required DateTimeOffset ScanTimestamp { get; init; }

    /// <summary>
    /// Signal Sentinel Scanner version.
    /// </summary>
    public required string ScannerVersion { get; init; }

    /// <summary>
    /// Scanned server summaries.
    /// </summary>
    public required IReadOnlyList<ServerScanSummary> Servers { get; init; }

    /// <summary>
    /// All findings across all servers.
    /// </summary>
    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>
    /// Cross-server attack paths detected.
    /// </summary>
    public required IReadOnlyList<AttackPath> AttackPaths { get; init; }

    /// <summary>
    /// Overall security score (A-F).
    /// </summary>
    public required SecurityGrade Grade { get; init; }

    /// <summary>
    /// Numeric score (0-100).
    /// </summary>
    public required int Score { get; init; }

    /// <summary>
    /// Summary statistics.
    /// </summary>
    public required ScanStatistics Statistics { get; init; }

    /// <summary>
    /// Skill scan summaries (empty if skill scanning was not performed).
    /// </summary>
    public IReadOnlyList<SkillScanSummary> Skills { get; init; } = [];

    /// <summary>
    /// v2.3.0: environment label ("dev", "staging", "prod", "default").
    /// </summary>
    public string Environment { get; init; } = "default";

    /// <summary>
    /// v2.3.0: scoring rubric version used to compute <see cref="Grade"/>. Stable across
    /// minor v2.x releases; changes trigger a major version bump.
    /// </summary>
    public string RubricVersion { get; init; } = "1.0";

    /// <summary>
    /// v2.3.0: explicit scope disclosure. Tells users what was and was not scanned.
    /// </summary>
    public ScanScope? Scope { get; init; }

    /// <summary>
    /// v2.3.0: suppressed findings retained separately for audit (accepted risks).
    /// </summary>
    public IReadOnlyList<Finding> SuppressedFindings { get; init; } = [];

    /// <summary>
    /// v2.3.0 fix (Section 0.4): what <see cref="Grade"/> would be if every
    /// suppression were removed. Null when there are no suppressions; otherwise
    /// lets reports show technical-debt exposure at a glance.
    /// </summary>
    public SecurityGrade? GradeWithoutSuppressions { get; init; }

    /// <summary>
    /// v2.3.0 fix (Section 0.4): what <see cref="Score"/> would be if every
    /// suppression were removed. Null when there are no suppressions.
    /// </summary>
    public int? ScoreWithoutSuppressions { get; init; }
}

/// <summary>
/// v2.3.0: explicit disclosure of what the scanner did and did not analyse. Surfaced
/// in every report format so users do not over-trust a clean report.
/// </summary>
public sealed record ScanScope
{
    /// <summary>
    /// What the scanner analysed (e.g. "SKILL.md", "YAML frontmatter", "bundled scripts surface").
    /// </summary>
    public IReadOnlyList<string> Scanned { get; init; } = [];

    /// <summary>
    /// What the scanner did not analyse (e.g. "transitive Python dependencies",
    /// "runtime behaviour").
    /// </summary>
    public IReadOnlyList<string> NotScanned { get; init; } = [];

    /// <summary>
    /// Complementary tools recommended by the operator (e.g. Bandit, Gitleaks, Semgrep).
    /// </summary>
    public IReadOnlyList<string> ComplementaryTools { get; init; } = [];
}

/// <summary>
/// Summary of a single skill scan.
/// </summary>
public sealed record SkillScanSummary
{
    /// <summary>
    /// Skill name.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Source platform (e.g., "Claude Code", "Cursor").
    /// </summary>
    public string? Platform { get; init; }

    /// <summary>
    /// File path to the SKILL.md file.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Number of bundled scripts found.
    /// </summary>
    public int ScriptCount { get; init; }

    /// <summary>
    /// Whether the skill is project-level.
    /// </summary>
    public bool IsProjectLevel { get; init; }
}

/// <summary>
/// Summary of a single server scan.
/// </summary>
public sealed record ServerScanSummary
{
    /// <summary>
    /// Server name.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Server version (if available).
    /// </summary>
    public string? Version { get; init; }

    /// <summary>
    /// Transport type used.
    /// </summary>
    public required string Transport { get; init; }

    /// <summary>
    /// Source configuration file.
    /// </summary>
    public string? SourceConfig { get; init; }

    /// <summary>
    /// Number of tools enumerated.
    /// </summary>
    public int ToolCount { get; init; }

    /// <summary>
    /// Number of resources enumerated.
    /// </summary>
    public int ResourceCount { get; init; }

    /// <summary>
    /// Number of prompts enumerated.
    /// </summary>
    public int PromptCount { get; init; }

    /// <summary>
    /// Whether the server was successfully connected.
    /// </summary>
    public bool ConnectionSuccessful { get; init; }

    /// <summary>
    /// Error message if connection failed.
    /// </summary>
    public string? ConnectionError { get; init; }
}

/// <summary>
/// Scan statistics summary.
/// </summary>
public sealed record ScanStatistics
{
    /// <summary>
    /// Total servers scanned.
    /// </summary>
    public int TotalServers { get; init; }

    /// <summary>
    /// Servers successfully connected.
    /// </summary>
    public int ServersConnected { get; init; }

    /// <summary>
    /// Total tools enumerated.
    /// </summary>
    public int TotalTools { get; init; }

    /// <summary>
    /// Total resources enumerated.
    /// </summary>
    public int TotalResources { get; init; }

    /// <summary>
    /// Total prompts enumerated.
    /// </summary>
    public int TotalPrompts { get; init; }

    /// <summary>
    /// Critical findings count.
    /// </summary>
    public int CriticalFindings { get; init; }

    /// <summary>
    /// High findings count.
    /// </summary>
    public int HighFindings { get; init; }

    /// <summary>
    /// Medium findings count.
    /// </summary>
    public int MediumFindings { get; init; }

    /// <summary>
    /// Low findings count.
    /// </summary>
    public int LowFindings { get; init; }

    /// <summary>
    /// Info findings count.
    /// </summary>
    public int InfoFindings { get; init; }

    /// <summary>
    /// Number of attack paths detected.
    /// </summary>
    public int AttackPathCount { get; init; }

    /// <summary>
    /// Total skills scanned.
    /// </summary>
    public int TotalSkills { get; init; }

    /// <summary>
    /// Total bundled scripts analysed across all skills.
    /// </summary>
    public int TotalScripts { get; init; }

    /// <summary>
    /// Scan duration in milliseconds.
    /// </summary>
    public long ScanDurationMs { get; init; }
}

/// <summary>
/// Security grade based on findings.
/// </summary>
public enum SecurityGrade
{
    /// <summary>
    /// A: No critical/high findings, no attack paths.
    /// </summary>
    A,

    /// <summary>
    /// B: No critical findings, minor highs.
    /// </summary>
    B,

    /// <summary>
    /// C: 1-2 high findings or 1 attack path.
    /// </summary>
    C,

    /// <summary>
    /// D: Critical findings present.
    /// </summary>
    D,

    /// <summary>
    /// F: Multiple critical findings or high-severity attack paths.
    /// </summary>
    F
}
