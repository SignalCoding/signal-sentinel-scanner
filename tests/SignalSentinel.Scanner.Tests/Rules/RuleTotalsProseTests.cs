// -----------------------------------------------------------------------
// <copyright file="RuleTotalsProseTests.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

// Sibling to RuleRegistryParityTests: that suite proves every *rule id* is named
// on every documentation surface, but it never checks that the *totals stated in
// prose* ("49 security rules (42 detection + 7 informational)") agree with the
// registry. SS-043 (ast04-metadata-integrity, PR #92) took the registry from 48
// to 49 rules and three prose totals - README.md, SECURITY.md and
// INSTALLATION_AND_USAGE.md - silently went stale; nothing failed. This is a
// separate test class (not an addition to RuleRegistryParityTests) because it
// answers a different question - "does the stated count agree with the
// registry" rather than "is every rule id named" - and needs its own file/line
// scanning machinery rather than the per-rule-id Theory shape above it.
//
// Scoping judgement calls:
//   - Ground truth comes from RuleEngine.CatalogueRules() (all 49 rules,
//     including the four Program.cs wires in per-scan), the same authoritative
//     source RuleRegistryParityTests.Rule_IsListedByListRulesCatalogue uses,
//     not a literal - so this test tracks the registry automatically as rules
//     are added or removed.
//   - Only three phrasings are matched: "<N> security rules", "<N> rules" and
//     "<N> detection + <M> informational". A bare number elsewhere in prose
//     (version numbers, OWASP-10 references, byte/KB sizes) has no "rule(s)"
//     word directly adjacent to it and is never matched.
//   - Release-history / changelog-style sections are excluded by heading: any
//     ATX heading (`#`.."######") whose text contains "what's new" or
//     "highlights" (case-insensitive) opens a historical block that runs until
//     the next heading of any level. README.md's "### What's new in v3.0.0"
//     section states "**15 new rules** (47 total)" - correct for that release
//     and must stay untouched - and sits inside such a block (confirmed this
//     line does not trip the total-rules regex anyway, since "new" separates
//     the number from the word "rules", but the heading exclusion is kept as a
//     second, independent layer of protection per the brief). Fenced code
//     blocks (```...```) are skipped entirely too, so an example command
//     containing a stray leading "#" (a bash comment) is never misread as a
//     markdown heading.
//   - A file that states no total at all (no line matches either phrasing) is
//     not a failure - the guard only fires when a stated number disagrees with
//     ground truth, never on absence.

using System.Globalization;
using System.Text.RegularExpressions;
using Shouldly;
using SignalSentinel.Core;
using SignalSentinel.Scanner.Rules;
using Xunit;

namespace SignalSentinel.Scanner.Tests.Rules;

public class RuleTotalsProseTests
{
    private static readonly string[] ProseFileNames =
        ["README.md", "SECURITY.md", "INSTALLATION_AND_USAGE.md"];

    private static readonly string[] HistoricalHeadingMarkers = ["what's new", "highlights"];

    // "<N> security rules" or "<N> rules" - the optional "security " is the only
    // word allowed between the number and "rule(s)", so a historical phrasing
    // like "15 new rules" (a different word in that slot) is never matched.
    private static readonly Regex TotalRulesStatement = new(
        @"(?<n>\d+)\s+(?:security\s+)?rules?\b",
        RegexOptions.None,
        TimeSpan.FromMilliseconds(RuleConstants.Limits.RegexTimeoutMs));

    // "<N> detection + <M> informational" - the parenthetical breakdown.
    private static readonly Regex DetectionInformationalStatement = new(
        @"(?<det>\d+)\s+detection\s*\+\s*(?<info>\d+)\s+informational",
        RegexOptions.None,
        TimeSpan.FromMilliseconds(RuleConstants.Limits.RegexTimeoutMs));

    private static readonly Regex AtxHeading = new(
        @"^\#{1,6}\s+(?<text>.+)$",
        RegexOptions.None,
        TimeSpan.FromMilliseconds(RuleConstants.Limits.RegexTimeoutMs));

    private static readonly Regex DetectionRuleId = new(
        @"^SS-\d+$",
        RegexOptions.None,
        TimeSpan.FromMilliseconds(RuleConstants.Limits.RegexTimeoutMs));

    private static string RepoRoot { get; } = ResolveRepoRoot();

    public static IEnumerable<object[]> ProseFiles =>
        ProseFileNames.Select(name => new object[] { name });

    [Theory]
    [MemberData(nameof(ProseFiles))]
    public void StatedRuleTotals_MatchRegistryGroundTruth(string relativePath)
    {
        var (total, detection, informational) = GroundTruth();
        var lines = File.ReadAllLines(Path.Combine(RepoRoot, relativePath));
        var offenders = new List<string>();
        var inFence = false;
        var inHistoricalSection = false;

        for (var lineIndex = 0; lineIndex < lines.Length; lineIndex++)
        {
            var line = lines[lineIndex];

            if (line.TrimStart().StartsWith("```", StringComparison.Ordinal))
            {
                inFence = !inFence;
                continue;
            }

            if (inFence)
            {
                continue;
            }

            var headingMatch = SafeMatch(AtxHeading, line);

            if (headingMatch.Success)
            {
                var headingText = headingMatch.Groups["text"].Value;
                inHistoricalSection = HistoricalHeadingMarkers.Any(marker =>
                    headingText.Contains(marker, StringComparison.OrdinalIgnoreCase));
                continue;
            }

            if (inHistoricalSection)
            {
                continue;
            }

            CheckTotalRulesStatement(line, relativePath, lineIndex + 1, total, offenders);
            CheckDetectionInformationalStatement(line, relativePath, lineIndex + 1, detection, informational, offenders);
        }

        offenders.ShouldBeEmpty(
            $"Stated rule total(s) in {relativePath} disagree with the registry " +
            $"({total} total, {detection} detection + {informational} informational):" +
            Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    private static void CheckTotalRulesStatement(
        string line, string relativePath, int lineNumber, int expectedTotal, List<string> offenders)
    {
        var match = SafeMatch(TotalRulesStatement, line);

        if (!match.Success)
        {
            return;
        }

        var found = int.Parse(match.Groups["n"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture);

        if (found != expectedTotal)
        {
            offenders.Add(
                $"{relativePath}:{lineNumber}: states {found} rule(s), registry has {expectedTotal} - " +
                line.Trim());
        }
    }

    private static void CheckDetectionInformationalStatement(
        string line,
        string relativePath,
        int lineNumber,
        int expectedDetection,
        int expectedInformational,
        List<string> offenders)
    {
        var match = SafeMatch(DetectionInformationalStatement, line);

        if (!match.Success)
        {
            return;
        }

        var foundDetection = int.Parse(match.Groups["det"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture);
        var foundInformational = int.Parse(match.Groups["info"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture);

        if (foundDetection != expectedDetection || foundInformational != expectedInformational)
        {
            offenders.Add(
                $"{relativePath}:{lineNumber}: states {foundDetection} detection + {foundInformational} informational, " +
                $"registry has {expectedDetection} detection + {expectedInformational} informational - " +
                line.Trim());
        }
    }

    private static (int Total, int Detection, int Informational) GroundTruth()
    {
        // Distinct: CatalogueRules() returns one IRule instance per registered rule
        // *implementation*, and SS-020 is intentionally emitted by two of them -
        // OAuthComplianceRule (protocol-level) and MissingAuthProbeRule (the
        // documented "behavioural SS-020" companion in RuleEngine's constructor
        // comment) - sharing one rule id by design. Ground truth here is "how many
        // distinct rule ids exist", which is what the prose totals describe.
        var ids = RuleEngine.CatalogueRules().Select(r => r.Id).Distinct(StringComparer.Ordinal).ToList();
        var informational = ids.Count(id => id.StartsWith("SS-INFO-", StringComparison.Ordinal));
        var detection = ids.Count(id => SafeIsMatch(DetectionRuleId, id));
        return (ids.Count, detection, informational);
    }

    private static Match SafeMatch(Regex pattern, string input)
    {
        try
        {
            return pattern.Match(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return Match.Empty;
        }
    }

    private static bool SafeIsMatch(Regex pattern, string input)
    {
        try
        {
            return pattern.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>
    /// Repo root located the same way <c>RuleRegistryParityTests.ResolveRepoRoot</c>
    /// and <c>VersionDriftTests.RepoRoot</c> do: the project directory is three
    /// levels above <see cref="AppContext.BaseDirectory"/> (bin/&lt;cfg&gt;/&lt;tfm&gt;),
    /// then two more levels up (tests/&lt;project&gt; -&gt; tests -&gt; repo root),
    /// confirmed by the presence of the solution file.
    /// </summary>
    private static string ResolveRepoRoot()
    {
        var projectDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
        var repoRoot = Path.GetFullPath(Path.Combine(projectDir, "..", ".."));

        if (File.Exists(Path.Combine(repoRoot, "signal-sentinel.sln")))
        {
            return repoRoot;
        }

        // Fallback for a copied-to-output layout (mirrors RealWorldSkillFixtures).
        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
    }
}
